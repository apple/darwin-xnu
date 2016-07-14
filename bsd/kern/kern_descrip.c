/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/guarded.h>
#include <sys/priv.h>
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
#include <kern/locks.h>
#include <sys/uio_internal.h>
#include <sys/codesign.h>
#include <sys/codedir_internal.h>

#include <security/audit/audit.h>

#include <sys/mount_internal.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/pipe.h>
#include <sys/spawn.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/waitq.h>
#include <libkern/OSAtomic.h>

#include <sys/ubc_internal.h>

#include <kern/ipc_misc.h>
#include <vm/vm_protos.h>

#include <mach/mach_port.h>
#include <stdbool.h>

#include <hfs/hfs.h>

kern_return_t ipc_object_copyin(ipc_space_t, mach_port_name_t,
    mach_msg_type_name_t, ipc_port_t *);
void ipc_port_release_send(ipc_port_t);

struct psemnode;
struct pshmnode;

static int finishdup(proc_t p,
    struct filedesc *fdp, int old, int new, int flags, int32_t *retval);

int falloc_locked(proc_t p, struct fileproc **resultfp, int *resultfd, vfs_context_t ctx, int locked);
void fg_drop(struct fileproc * fp);
void fg_free(struct fileglob *fg);
void fg_ref(struct fileproc * fp);
void fileport_releasefg(struct fileglob *fg);

/* flags for close_internal_locked */
#define FD_DUP2RESV 1

/* We don't want these exported */

__private_extern__
int unlink1(vfs_context_t, vnode_t, user_addr_t, enum uio_seg, int);

static void _fdrelse(struct proc * p, int fd);


extern void file_lock_init(void);

extern kauth_scope_t	kauth_scope_fileop;

/* Conflict wait queue for when selects collide (opaque type) */
extern struct waitq select_conflict_queue;

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_ops->fo_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
#define CHECK_ADD_OVERFLOW_INT64L(x, y) \
		(((((x) > 0) && ((y) > 0) && ((x) > LLONG_MAX - (y))) || \
		(((x) < 0) && ((y) < 0) && ((x) < LLONG_MIN - (y)))) \
		? 1 : 0)
/*
 * Descriptor management.
 */
struct fmsglist fmsghead;	/* head of list of open files */
struct fmsglist fmsg_ithead;	/* head of list of open files */
int nfiles;			/* actual number of open files */


lck_grp_attr_t * file_lck_grp_attr;
lck_grp_t * file_lck_grp;
lck_attr_t * file_lck_attr;

lck_mtx_t * uipc_lock;


/*
 * check_file_seek_range
 *
 * Description: Checks if seek offsets are in the range of 0 to LLONG_MAX.
 *
 * Parameters:  fl		Flock structure.
 *		cur_file_offset	Current offset in the file.
 *
 * Returns: 	0 		on Success.
 *		EOVERFLOW	on overflow.
 *		EINVAL   	on offset less than zero.
 */

static int
check_file_seek_range(struct flock *fl, off_t cur_file_offset)
{
	if (fl->l_whence == SEEK_CUR) {
		/* Check if the start marker is beyond LLONG_MAX. */
		if (CHECK_ADD_OVERFLOW_INT64L(fl->l_start, cur_file_offset)) {
			/* Check if start marker is negative */
			if (fl->l_start < 0) {
				return EINVAL;
			}
			return EOVERFLOW;
		}
		/* Check if the start marker is negative. */
		if (fl->l_start + cur_file_offset < 0) {
			return EINVAL;
		}
		/* Check if end marker is beyond LLONG_MAX. */
		if ((fl->l_len > 0) && (CHECK_ADD_OVERFLOW_INT64L(fl->l_start + 
			cur_file_offset, fl->l_len - 1))) {
			return EOVERFLOW;
		}
		/* Check if the end marker is negative. */
		if ((fl->l_len <= 0) && (fl->l_start + cur_file_offset +
			fl->l_len < 0)) {
			return EINVAL;
		}
	} else if (fl->l_whence == SEEK_SET) {
		/* Check if the start marker is negative. */
		if (fl->l_start < 0) {
			return EINVAL;
		}
		/* Check if the end marker is beyond LLONG_MAX. */
		if ((fl->l_len > 0) && 
		    CHECK_ADD_OVERFLOW_INT64L(fl->l_start, fl->l_len - 1)) {
			return EOVERFLOW;
		}
		/* Check if the end marker is negative. */
		if ((fl->l_len < 0) &&  fl->l_start + fl->l_len < 0) {
			return EINVAL;
		}
	}
	return 0;
}


/*
 * file_lock_init
 *
 * Description:	Initialize the file lock group and the uipc and flist locks
 *
 * Parameters:	(void)
 *
 * Returns:	void
 *
 * Notes:	Called at system startup from bsd_init().
 */
void
file_lock_init(void)
{
	/* allocate file lock group attribute and group */
	file_lck_grp_attr= lck_grp_attr_alloc_init();

	file_lck_grp = lck_grp_alloc_init("file",  file_lck_grp_attr);

	/* Allocate file lock attribute */
	file_lck_attr = lck_attr_alloc_init();

	uipc_lock = lck_mtx_alloc_init(file_lck_grp, file_lck_attr);
}


/*
 * proc_fdlock, proc_fdlock_spin
 *
 * Description:	Lock to control access to the per process struct fileproc
 *		and struct filedesc
 *
 * Parameters:	p				Process to take the lock on
 *
 * Returns:	void
 *
 * Notes:	The lock is initialized in forkproc() and destroyed in
 *		reap_child_process().
 */
void
proc_fdlock(proc_t p)
{
	lck_mtx_lock(&p->p_fdmlock);
}

void
proc_fdlock_spin(proc_t p)
{
	lck_mtx_lock_spin(&p->p_fdmlock);
}

void
proc_fdlock_assert(proc_t p, int assertflags)
{
	lck_mtx_assert(&p->p_fdmlock, assertflags);
}


/*
 * proc_fdunlock
 *
 * Description:	Unlock the lock previously locked by a call to proc_fdlock()
 *
 * Parameters:	p				Process to drop the lock on
 *
 * Returns:	void
 */
void
proc_fdunlock(proc_t p)
{
	lck_mtx_unlock(&p->p_fdmlock);
}


/*
 * System calls on descriptors.
 */


/*
 * getdtablesize
 *
 * Description:	Returns the per process maximum size of the descriptor table
 *
 * Parameters:	p				Process being queried
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *
 * Implicit returns:
 *		*retval (modified)		Size of dtable
 */
int
getdtablesize(proc_t p, __unused struct getdtablesize_args *uap, int32_t *retval)
{
	proc_fdlock_spin(p);
	*retval = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	proc_fdunlock(p);

	return (0);
}


void
procfdtbl_reservefd(struct proc * p, int fd)
{
	p->p_fd->fd_ofiles[fd] = NULL;
        p->p_fd->fd_ofileflags[fd] |= UF_RESERVED;
}

void
procfdtbl_markclosefd(struct proc * p, int fd)
{
        p->p_fd->fd_ofileflags[fd] |= (UF_RESERVED | UF_CLOSING);
}

void
procfdtbl_releasefd(struct proc * p, int fd, struct fileproc * fp)
{
	if (fp != NULL)
        	p->p_fd->fd_ofiles[fd] = fp;
        p->p_fd->fd_ofileflags[fd] &= ~UF_RESERVED;
	if ((p->p_fd->fd_ofileflags[fd] & UF_RESVWAIT) == UF_RESVWAIT) {
		p->p_fd->fd_ofileflags[fd] &= ~UF_RESVWAIT;
		wakeup(&p->p_fd);
	}
}

void 
procfdtbl_waitfd(struct proc * p, int fd)
{
        p->p_fd->fd_ofileflags[fd] |= UF_RESVWAIT;
	msleep(&p->p_fd, &p->p_fdmlock, PRIBIO, "ftbl_waitfd", NULL);
}


void
procfdtbl_clearfd(struct proc * p, int fd)
{
	int waiting;

	waiting = (p->p_fd->fd_ofileflags[fd] & UF_RESVWAIT);
	p->p_fd->fd_ofiles[fd] = NULL;       
	p->p_fd->fd_ofileflags[fd] = 0;
	if ( waiting == UF_RESVWAIT) {
		wakeup(&p->p_fd);
	}
}

/*
 * _fdrelse
 *
 * Description:	Inline utility function to free an fd in a filedesc
 *
 * Parameters:	fdp				Pointer to filedesc fd lies in
 *		fd				fd to free
 *		reserv				fd should be reserved
 *
 * Returns:	void
 *
 * Locks:	Assumes proc_fdlock for process pointing to fdp is held by
 *		the caller
 */
static void
_fdrelse(struct proc * p, int fd)
{
	struct filedesc *fdp = p->p_fd;
	int nfd = 0;

	if (fd < fdp->fd_freefile)
		fdp->fd_freefile = fd;
#if DIAGNOSTIC
	if (fd > fdp->fd_lastfile)
 		panic("fdrelse: fd_lastfile inconsistent");
#endif
	procfdtbl_clearfd(p, fd);

	while ((nfd = fdp->fd_lastfile) > 0 &&
			fdp->fd_ofiles[nfd] == NULL &&
			!(fdp->fd_ofileflags[nfd] & UF_RESERVED))
		fdp->fd_lastfile--;
}


int
fd_rdwr(
	int fd,
	enum uio_rw rw,
	uint64_t base,
	int64_t len,
	enum uio_seg segflg,
	off_t	offset,
	int	io_flg,
	int64_t *aresid)
{
        struct fileproc *fp;
	proc_t	p;
        int error = 0;
	int flags = 0;
	int spacetype;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
	struct vfs_context context = *(vfs_context_current());
	bool wrote_some = false;

	p = current_proc();

        error = fp_lookup(p, fd, &fp, 0);
        if (error)
                return(error);

	if (fp->f_type != DTYPE_VNODE && fp->f_type != DTYPE_PIPE && fp->f_type != DTYPE_SOCKET) {
		error = EINVAL;
		goto out;
	}
	if (rw == UIO_WRITE && !(fp->f_flag & FWRITE)) {
                error = EBADF;
		goto out;
	}
	
	if (rw == UIO_READ && !(fp->f_flag & FREAD)) {
    		error = EBADF;
    		goto out;
	}
	
	context.vc_ucred = fp->f_fglob->fg_cred;

	if (UIO_SEG_IS_USER_SPACE(segflg))
		spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	else
		spacetype = UIO_SYSSPACE;

	auio = uio_createwithbuffer(1, offset, spacetype, rw, &uio_buf[0], sizeof(uio_buf));

	uio_addiov(auio, base, len);

	if ( !(io_flg & IO_APPEND))
		flags = FOF_OFFSET;

	if (rw == UIO_WRITE) {
		user_ssize_t orig_resid = uio_resid(auio);
		error = fo_write(fp, auio, flags, &context);
		wrote_some = uio_resid(auio) < orig_resid;
	} else
		error = fo_read(fp, auio, flags, &context);

	if (aresid)
		*aresid = uio_resid(auio);
	else {
		if (uio_resid(auio) && error == 0)
			error = EIO;
	}
out:
        if (wrote_some)
                fp_drop_written(p, fd, fp);
        else
                fp_drop(p, fd, fp, 0);

	return error;
}



/*
 * dup
 *
 * Description:	Duplicate a file descriptor.
 *
 * Parameters:	p				Process performing the dup
 *		uap->fd				The fd to dup
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		!0				Errno
 *
 * Implicit returns:
 *		*retval (modified)		The new descriptor
 */
int
dup(proc_t p, struct dup_args *uap, int32_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int old = uap->fd;
	int new, error;
	struct fileproc *fp;

	proc_fdlock(p);
	if ( (error = fp_lookup(p, old, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (FP_ISGUARDED(fp, GUARD_DUP)) {
		error = fp_guard_exception(p, old, fp, kGUARD_EXC_DUP);
		(void) fp_drop(p, old, fp, 1);
		proc_fdunlock(p);
		return (error);
	}
	if ( (error = fdalloc(p, 0, &new)) ) {
		fp_drop(p, old, fp, 1);
		proc_fdunlock(p);
		return (error);
	}
	error = finishdup(p, fdp, old, new, 0, retval);
	fp_drop(p, old, fp, 1);
	proc_fdunlock(p);

	if (ENTR_SHOULDTRACE && fp->f_type == DTYPE_SOCKET) {
		KERNEL_ENERGYTRACE(kEnTrActKernSocket, DBG_FUNC_START,
		    new, 0, (int64_t)VM_KERNEL_ADDRPERM(fp->f_data));
	}

	return (error);
}

/*
 * dup2
 *
 * Description:	Duplicate a file descriptor to a particular value.
 *
 * Parameters:	p				Process performing the dup
 *		uap->from			The fd to dup
 *		uap->to				The fd to dup it to
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		!0				Errno
 *
 * Implicit returns:
 *		*retval (modified)		The new descriptor
 */
int
dup2(proc_t p, struct dup2_args *uap, int32_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int old = uap->from, new = uap->to;
	int i, error;
	struct fileproc *fp, *nfp;

	proc_fdlock(p);

startover:
	if ( (error = fp_lookup(p, old, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (FP_ISGUARDED(fp, GUARD_DUP)) {
		error = fp_guard_exception(p, old, fp, kGUARD_EXC_DUP);
		(void) fp_drop(p, old, fp, 1);
		proc_fdunlock(p);
		return (error);
	}
	if (new < 0 ||
		(rlim_t)new >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
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
			fdrelse(p, i);
			goto closeit;
		}
	} else {
closeit:
		while ((fdp->fd_ofileflags[new] & UF_RESERVED) == UF_RESERVED)  {
				fp_drop(p, old, fp, 1);
				procfdtbl_waitfd(p, new);
#if DIAGNOSTIC
				proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif
				goto startover;
		}

		if ((fdp->fd_ofiles[new] != NULL) &&
		    ((error = fp_lookup(p, new, &nfp, 1)) == 0)) {
			fp_drop(p, old, fp, 1);
			if (FP_ISGUARDED(nfp, GUARD_CLOSE)) {
				error = fp_guard_exception(p,
				    new, nfp, kGUARD_EXC_CLOSE);
				(void) fp_drop(p, new, nfp, 1);
				proc_fdunlock(p);
				return (error);
			}
			(void)close_internal_locked(p, new, nfp, FD_DUP2RESV);
#if DIAGNOSTIC
			proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif
			procfdtbl_clearfd(p, new);
			goto startover;
		} else  {
#if DIAGNOSTIC
			if (fdp->fd_ofiles[new] != NULL)
				panic("dup2: no ref on fileproc %d", new);
#endif
			procfdtbl_reservefd(p, new);
		}

#if DIAGNOSTIC
		proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif

	}
#if DIAGNOSTIC
	if (fdp->fd_ofiles[new] != 0)
		panic("dup2: overwriting fd_ofiles with new %d", new);
	if ((fdp->fd_ofileflags[new] & UF_RESERVED) == 0)
		panic("dup2: unreserved fileflags with new %d", new);
#endif
	error = finishdup(p, fdp, old, new, 0, retval);
	fp_drop(p, old, fp, 1);
	proc_fdunlock(p);

	return(error);
}


/*
 * fcntl
 *
 * Description:	The file control system call.
 *
 * Parameters:	p				Process performing the fcntl
 *		uap->fd				The fd to operate against
 *		uap->cmd			The command to perform
 *		uap->arg			Pointer to the command argument
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		!0				Errno (see fcntl_nocancel)
 *
 * Implicit returns:
 *		*retval (modified)		fcntl return value (if any)
 *
 * Notes:	This system call differs from fcntl_nocancel() in that it
 *		tests for cancellation prior to performing a potentially
 *		blocking operation.
 */
int
fcntl(proc_t p, struct fcntl_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(fcntl_nocancel(p, (struct fcntl_nocancel_args *)uap, retval));
}


/*
 * fcntl_nocancel
 *
 * Description:	A non-cancel-testing file control system call.
 *
 * Parameters:	p				Process performing the fcntl
 *		uap->fd				The fd to operate against
 *		uap->cmd			The command to perform
 *		uap->arg			Pointer to the command argument
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		EINVAL
 *	fp_lookup:EBADF				Bad file descriptor
 * [F_DUPFD]
 *	fdalloc:EMFILE
 *	fdalloc:ENOMEM
 *	finishdup:EBADF
 *	finishdup:ENOMEM
 * [F_SETOWN]
 *		ESRCH
 * [F_SETLK]
 *		EBADF
 *		EOVERFLOW
 *	copyin:EFAULT
 *	vnode_getwithref:???
 *	VNOP_ADVLOCK:???
 *	msleep:ETIMEDOUT
 * [F_GETLK]
 *		EBADF
 *		EOVERFLOW
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	vnode_getwithref:???
 *	VNOP_ADVLOCK:???
 * [F_PREALLOCATE]
 *		EBADF
 *		EINVAL
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	vnode_getwithref:???
 *	VNOP_ALLOCATE:???
 * [F_SETSIZE,F_RDADVISE]
 *		EBADF
 *	copyin:EFAULT
 *	vnode_getwithref:???
 * [F_RDAHEAD,F_NOCACHE]
 *		EBADF
 *	vnode_getwithref:???
 * [???]
 *
 * Implicit returns:
 *		*retval (modified)		fcntl return value (if any)
 */
int
fcntl_nocancel(proc_t p, struct fcntl_nocancel_args *uap, int32_t *retval)
{
	int fd = uap->fd;
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;
	char *pop;
	struct vnode *vp = NULLVP;	/* for AUDIT_ARG() at end */
	int i, tmp, error, error2, flg = 0;
	struct flock fl;
	struct flocktimeout fltimeout;
	struct timespec *timeout = NULL;
	struct vfs_context context;
	off_t offset;
	int newmin;
	daddr64_t lbn, bn;
	unsigned int fflag;
	user_addr_t argp;
	boolean_t is64bit;

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(cmd, uap->cmd);

	proc_fdlock(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	context.vc_thread = current_thread();
	context.vc_ucred = fp->f_cred;

	is64bit = proc_is64bit(p);
	if (is64bit) {
		argp = uap->arg;
	}
	else {
		/*
		 * Since the arg parameter is defined as a long but may be
		 * either a long or a pointer we must take care to handle
		 * sign extension issues.  Our sys call munger will sign
		 * extend a long when we are called from a 32-bit process.
		 * Since we can never have an address greater than 32-bits
		 * from a 32-bit process we lop off the top 32-bits to avoid
		 * getting the wrong address
		 */
		argp = CAST_USER_ADDR_T((uint32_t)uap->arg);
	}

	pop = &fdp->fd_ofileflags[fd];

#if CONFIG_MACF
	error = mac_file_check_fcntl(proc_ucred(p), fp->f_fglob, uap->cmd,
	    uap->arg);
	if (error)
		goto out;
#endif

	switch (uap->cmd) {

	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		if (FP_ISGUARDED(fp, GUARD_DUP)) {
			error = fp_guard_exception(p, fd, fp, kGUARD_EXC_DUP);
			goto out;
		}
		newmin = CAST_DOWN_EXPLICIT(int, uap->arg); /* arg is an int, so we won't lose bits */
		AUDIT_ARG(value32, newmin);
		if ((u_int)newmin >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
		    newmin >= maxfiles) {
			error = EINVAL;
			goto out;
		}
		if ( (error = fdalloc(p, newmin, &i)) )
			goto out;
		error = finishdup(p, fdp, fd, i,
		    uap->cmd == F_DUPFD_CLOEXEC ? UF_EXCLOSE : 0, retval);
		goto out;

	case F_GETFD:
		*retval = (*pop & UF_EXCLOSE)? FD_CLOEXEC : 0;
		error = 0;
		goto out;

	case F_SETFD:
		AUDIT_ARG(value32, uap->arg);
		if (uap->arg & FD_CLOEXEC)
			*pop |= UF_EXCLOSE;
		else {
			if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
				error = fp_guard_exception(p,
				    fd, fp, kGUARD_EXC_NOCLOEXEC);
				goto out;
			}
			*pop &= ~UF_EXCLOSE;
		}
		error = 0;
		goto out;

	case F_GETFL:
		*retval = OFLAGS(fp->f_flag);
		error = 0;
		goto out;

	case F_SETFL:
		fp->f_flag &= ~FCNTLFLAGS;
		tmp = CAST_DOWN_EXPLICIT(int, uap->arg); /* arg is an int, so we won't lose bits */
		AUDIT_ARG(value32, tmp);
		fp->f_flag |= FFLAGS(tmp) & FCNTLFLAGS;
		tmp = fp->f_flag & FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, &context);
		if (error)
			goto out;
		tmp = fp->f_flag & FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, &context);
		if (!error)
			goto out;
		fp->f_flag &= ~FNONBLOCK;
		tmp = 0;
		(void)fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, &context);
		goto out;

	case F_GETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			*retval = ((struct socket *)fp->f_data)->so_pgid;
			error = 0;
			goto out;
		}
		error = fo_ioctl(fp, (int)TIOCGPGRP, (caddr_t)retval, &context);
		*retval = -*retval;
		goto out;

	case F_SETOWN:
		tmp = CAST_DOWN_EXPLICIT(pid_t, uap->arg); /* arg is an int, so we won't lose bits */
		AUDIT_ARG(value32, tmp);
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			error =0;
			goto out;
		}
		if (fp->f_type == DTYPE_PIPE) {
			error =  fo_ioctl(fp, TIOCSPGRP, (caddr_t)&tmp, &context);
			goto out;
		}

		if (tmp <= 0) {
			tmp = -tmp;
		} else {
			proc_t p1 = proc_find(tmp);
			if (p1 == 0) {
				error = ESRCH;
				goto out;
			}
			tmp = (int)p1->p_pgrpid;
			proc_rele(p1);
		}
		error =  fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, &context);
		goto out;

	case F_SETNOSIGPIPE:
		tmp = CAST_DOWN_EXPLICIT(int, uap->arg);
		if (fp->f_type == DTYPE_SOCKET) {
#if SOCKETS
			error = sock_setsockopt((struct socket *)fp->f_data,
			    SOL_SOCKET, SO_NOSIGPIPE, &tmp, sizeof (tmp));
#else
			error = EINVAL;
#endif
		} else {
			struct fileglob *fg = fp->f_fglob;

			lck_mtx_lock_spin(&fg->fg_lock);
			if (tmp)
				fg->fg_lflags |= FG_NOSIGPIPE;
			else
				fg->fg_lflags &= FG_NOSIGPIPE;
			lck_mtx_unlock(&fg->fg_lock);
			error = 0;
		}
		goto out;

	case F_GETNOSIGPIPE:
		if (fp->f_type == DTYPE_SOCKET) {
#if SOCKETS
			int retsize = sizeof (*retval);
			error = sock_getsockopt((struct socket *)fp->f_data,
			    SOL_SOCKET, SO_NOSIGPIPE, retval, &retsize);
#else
			error = EINVAL;
#endif
		} else {
			*retval = (fp->f_fglob->fg_lflags & FG_NOSIGPIPE) ?
				1 : 0;
			error = 0;
		}
		goto out;

	case F_SETCONFINED:
		/*
		 * If this is the only reference to this fglob in the process
		 * and it's already marked as close-on-fork then mark it as
		 * (immutably) "confined" i.e. any fd that points to it will
		 * forever be close-on-fork, and attempts to use an IPC
		 * mechanism to move the descriptor elsewhere will fail.
		 */
		if (CAST_DOWN_EXPLICIT(int, uap->arg)) {
			struct fileglob *fg = fp->f_fglob;

			lck_mtx_lock_spin(&fg->fg_lock);
			if (fg->fg_lflags & FG_CONFINED)
				error = 0;
			else if (1 != fg->fg_count)
				error = EAGAIN;	/* go close the dup .. */
			else if (UF_FORKCLOSE == (*pop & UF_FORKCLOSE)) {
				fg->fg_lflags |= FG_CONFINED;
				error = 0;
			} else
				error = EBADF;	/* open without O_CLOFORK? */
			lck_mtx_unlock(&fg->fg_lock);
		} else {
			/*
			 * Other subsystems may have built on the immutability
			 * of FG_CONFINED; clearing it may be tricky.
			 */
			error = EPERM;		/* immutable */
		}
		goto out;

	case F_GETCONFINED:
		*retval = (fp->f_fglob->fg_lflags & FG_CONFINED) ? 1 : 0;
		error = 0;
		goto out;

	case F_SETLKWTIMEOUT:
	case F_SETLKW:
	case F_OFD_SETLKWTIMEOUT:
	case F_OFD_SETLKW:
		flg |= F_WAIT;
		/* Fall into F_SETLK */

	case F_SETLK:
	case F_OFD_SETLK:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		fflag = fp->f_flag;
		offset = fp->f_offset;
		proc_fdunlock(p);

		/* Copy in the lock structure */
		if (F_SETLKWTIMEOUT == uap->cmd ||
		    F_OFD_SETLKWTIMEOUT == uap->cmd) {
			error = copyin(argp, (caddr_t) &fltimeout, sizeof(fltimeout));
			if (error) {
				goto outdrop;
			}
			fl = fltimeout.fl;
			timeout = &fltimeout.timeout;
		} else {
			error = copyin(argp, (caddr_t)&fl, sizeof(fl));
			if (error) {
				goto outdrop;
			}
		}

		/* Check starting byte and ending byte for EOVERFLOW in SEEK_CUR */
		/* and ending byte for EOVERFLOW in SEEK_SET */
		error = check_file_seek_range(&fl, offset);
		if (error) {
			goto outdrop;
		}

		if ( (error = vnode_getwithref(vp)) ) {
			goto outdrop;
		}
		if (fl.l_whence == SEEK_CUR)
			fl.l_start += offset;

#if CONFIG_MACF
		error = mac_file_check_lock(proc_ucred(p), fp->f_fglob,
		    F_SETLK, &fl);
		if (error) {
			(void)vnode_put(vp);
			goto outdrop;
		}
#endif
		switch (uap->cmd) {
		case F_OFD_SETLK:
		case F_OFD_SETLKW:
		case F_OFD_SETLKWTIMEOUT:
			flg |= F_OFD_LOCK;
			switch (fl.l_type) {
			case F_RDLCK:
				if ((fflag & FREAD) == 0) {
					error = EBADF;
					break;
				}
				error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob,
				    F_SETLK, &fl, flg, &context, timeout);
				break;
			case F_WRLCK:
				if ((fflag & FWRITE) == 0) {
					error = EBADF;
					break;
				}
				error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob,
				    F_SETLK, &fl, flg, &context, timeout);
				break;
			case F_UNLCK:
				error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob,
				    F_UNLCK, &fl, F_OFD_LOCK, &context,
				    timeout);
				break;
			default:
				error = EINVAL;
				break;
			}
			if (0 == error &&
			    (F_RDLCK == fl.l_type || F_WRLCK == fl.l_type)) {
				struct fileglob *fg = fp->f_fglob;

				/*
				 * arrange F_UNLCK on last close (once
				 * set, FG_HAS_OFDLOCK is immutable)
				 */
				if ((fg->fg_lflags & FG_HAS_OFDLOCK) == 0) {
					lck_mtx_lock_spin(&fg->fg_lock);
					fg->fg_lflags |= FG_HAS_OFDLOCK;
					lck_mtx_unlock(&fg->fg_lock);
				}
			}
			break;
		default:
			flg |= F_POSIX;
			switch (fl.l_type) {
			case F_RDLCK:
				if ((fflag & FREAD) == 0) {
					error = EBADF;
					break;
				}
				// XXX UInt32 unsafe for LP64 kernel
				OSBitOrAtomic(P_LADVLOCK, &p->p_ladvflag);
				error = VNOP_ADVLOCK(vp, (caddr_t)p,
				    F_SETLK, &fl, flg, &context, timeout);
				break;
			case F_WRLCK:
				if ((fflag & FWRITE) == 0) {
					error = EBADF;
					break;
				}
				// XXX UInt32 unsafe for LP64 kernel
				OSBitOrAtomic(P_LADVLOCK, &p->p_ladvflag);
				error = VNOP_ADVLOCK(vp, (caddr_t)p,
				    F_SETLK, &fl, flg, &context, timeout);
				break;
			case F_UNLCK:
				error = VNOP_ADVLOCK(vp, (caddr_t)p,
				    F_UNLCK, &fl, F_POSIX, &context, timeout);
				break;
			default:
				error = EINVAL;
				break;
			}
			break;
		}
		(void) vnode_put(vp);
		goto outdrop;

	case F_GETLK:
	case F_OFD_GETLK:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		offset = fp->f_offset;
		proc_fdunlock(p);

		/* Copy in the lock structure */
		error = copyin(argp, (caddr_t)&fl, sizeof(fl));
		if (error)
			goto outdrop;

		/* Check starting byte and ending byte for EOVERFLOW in SEEK_CUR */
		/* and ending byte for EOVERFLOW in SEEK_SET */
		error = check_file_seek_range(&fl, offset);
		if (error) {
			goto outdrop;
		}

		if ((fl.l_whence == SEEK_SET) && (fl.l_start < 0)) {
			error = EINVAL;
			goto outdrop;
		}

		switch (fl.l_type) {
		case F_RDLCK:
		case F_UNLCK:
		case F_WRLCK:
			break;
		default:
			error = EINVAL;
			goto outdrop;
		}

		switch (fl.l_whence) {
		case SEEK_CUR:
		case SEEK_SET:
		case SEEK_END:
			break;
		default:
			error = EINVAL;
			goto outdrop;
		}

		if ( (error = vnode_getwithref(vp)) == 0 ) {
			if (fl.l_whence == SEEK_CUR)
			        fl.l_start += offset;

#if CONFIG_MACF
			error = mac_file_check_lock(proc_ucred(p), fp->f_fglob,
			    uap->cmd, &fl);
			if (error == 0)
#endif
			switch (uap->cmd) {
			case F_OFD_GETLK:
				error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob,
				    F_GETLK, &fl, F_OFD_LOCK, &context, NULL);
				break;
			case F_OFD_GETLKPID:
				error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob,
				    F_GETLKPID, &fl, F_OFD_LOCK, &context, NULL);
				break;
			default:
				error = VNOP_ADVLOCK(vp, (caddr_t)p,
				    uap->cmd, &fl, F_POSIX, &context, NULL);
				break;
			}

			(void)vnode_put(vp);

			if (error == 0)
				error = copyout((caddr_t)&fl, argp, sizeof(fl));
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

		error = copyin(argp, (caddr_t)&alloc_struct, sizeof(alloc_struct));
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

			error2 = copyout((caddr_t)&alloc_struct, argp, sizeof(alloc_struct));

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
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		error = copyin(argp, (caddr_t)&offset, sizeof (off_t));
		if (error)
			goto outdrop;
		AUDIT_ARG(value64, offset);

		error = vnode_getwithref(vp);
		if (error)
			goto outdrop;

#if CONFIG_MACF
		error = mac_vnode_check_truncate(&context,
		    fp->f_fglob->fg_cred, vp);
		if (error) {
			(void)vnode_put(vp);
			goto outdrop;
		}
#endif
		/*
		 * Make sure that we are root.  Growing a file
		 * without zero filling the data is a security hole 
		 * root would have access anyway so we'll allow it
		 */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			error = EACCES;
		} else {
			/*
			 * set the file size
			 */
			error = vnode_setsize(vp, offset, IO_NOZEROFILL,
			    &context);
		}

		(void)vnode_put(vp);
		goto outdrop;

	case F_RDAHEAD:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		if (uap->arg)
		        fp->f_fglob->fg_flag &= ~FNORDAHEAD;
		else
		        fp->f_fglob->fg_flag |= FNORDAHEAD;

		goto out;

	case F_NOCACHE:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		if (uap->arg)
		        fp->f_fglob->fg_flag |= FNOCACHE;
		else
		        fp->f_fglob->fg_flag &= ~FNOCACHE;

		goto out;

	case F_NODIRECT:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		if (uap->arg)
		        fp->f_fglob->fg_flag |= FNODIRECT;
		else
		        fp->f_fglob->fg_flag &= ~FNODIRECT;

		goto out;

	case F_SINGLE_WRITER:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		if (uap->arg)
		        fp->f_fglob->fg_flag |= FSINGLE_WRITER;
		else
		        fp->f_fglob->fg_flag &= ~FSINGLE_WRITER;

		goto out;

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

	case F_CHECK_OPENEVT:
	        if (fp->f_type != DTYPE_VNODE) {
		        error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {

		        *retval = vnode_is_openevt(vp);

			if (uap->arg)
			        vnode_set_openevt(vp);
			else
			        vnode_clear_openevt(vp);

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

		if ( (error = copyin(argp, (caddr_t)&ra_struct, sizeof(ra_struct))) )
			goto outdrop;
		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        error = VNOP_IOCTL(vp, F_RDADVISE, (caddr_t)&ra_struct, 0, &context);

			(void)vnode_put(vp);
		}
		goto outdrop;
		}

        case F_FLUSH_DATA:

                if (fp->f_type != DTYPE_VNODE) {
                        error = EBADF;
                        goto out;
                }
                vp = (struct vnode *)fp->f_data;
                proc_fdunlock(p);

                if ( (error = vnode_getwithref(vp)) == 0 ) {
                        error = cluster_push(vp, 0);

                        (void)vnode_put(vp);
                }
                goto outdrop;

	case F_LOG2PHYS:
	case F_LOG2PHYS_EXT: {
		struct log2phys l2p_struct;    /* structure for allocate command */
		int devBlockSize;

		off_t file_offset = 0;
		size_t a_size = 0;
		size_t run = 0;

		if (uap->cmd == F_LOG2PHYS_EXT) {
			error = copyin(argp, (caddr_t)&l2p_struct, sizeof(l2p_struct));
			if (error)
				goto out;
			file_offset = l2p_struct.l2p_devoffset;
		} else {
			file_offset = fp->f_offset;
		}
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);
		if ( (error = vnode_getwithref(vp)) ) {
			goto outdrop;
		}
		error = VNOP_OFFTOBLK(vp, file_offset, &lbn);
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
		if (uap->cmd == F_LOG2PHYS_EXT) {
			if (l2p_struct.l2p_contigbytes < 0) {
				vnode_put(vp);
				error = EINVAL;
				goto outdrop;
			}

			a_size = MIN((uint64_t)l2p_struct.l2p_contigbytes, SIZE_MAX);
		} else {
			a_size = devBlockSize;
		}
		
		error = VNOP_BLOCKMAP(vp, offset, a_size, &bn, &run, NULL, 0, &context);

		(void)vnode_put(vp);

		if (!error) {
			l2p_struct.l2p_flags = 0;	/* for now */
			if (uap->cmd == F_LOG2PHYS_EXT) {
				l2p_struct.l2p_contigbytes = run - (file_offset - offset);
			} else {
				l2p_struct.l2p_contigbytes = 0;	/* for now */
			}

			/*
			 * The block number being -1 suggests that the file offset is not backed
			 * by any real blocks on-disk.  As a result, just let it be passed back up wholesale.
			 */
			if (bn == -1) {
				/* Don't multiply it by the block size */
				l2p_struct.l2p_devoffset = bn;
			}
			else {
				l2p_struct.l2p_devoffset = bn * devBlockSize;
				l2p_struct.l2p_devoffset += file_offset - offset;
			}
			error = copyout((caddr_t)&l2p_struct, argp, sizeof(l2p_struct));
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
				AUDIT_ARG(text, pathbufp);
			        error = vn_path_package_check(vp, pathbufp, pathlen, retval);

				(void)vnode_put(vp);
			}
		}
		kfree(pathbufp, MAXPATHLEN);
		goto outdrop;
	}

	case F_CHKCLEAN:   // used by regression tests to see if all dirty pages got cleaned by fsync()
	case F_FULLFSYNC:  // fsync + flush the journal + DKIOCSYNCHRONIZE
	case F_BARRIERFSYNC:  // fsync + barrier
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

	/*
	 * SPI (private) for opening a file starting from a dir fd
	 */
	case F_OPENFROM: {
		struct user_fopenfrom fopen;
		struct vnode_attr va;
		struct nameidata nd;
		int cmode;

		/* Check if this isn't a valid file descriptor */
		if ((fp->f_type != DTYPE_VNODE) ||
		    (fp->f_flag & FREAD) == 0) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}
		
		/* Only valid for directories */
		if (vp->v_type != VDIR) {
			vnode_put(vp);
			error = ENOTDIR;
			goto outdrop;
		}

		/* Get flags, mode and pathname arguments. */
		if (IS_64BIT_PROCESS(p)) {
			error = copyin(argp, &fopen, sizeof(fopen));
		} else {
			struct user32_fopenfrom fopen32;

			error = copyin(argp, &fopen32, sizeof(fopen32));
			fopen.o_flags = fopen32.o_flags;
			fopen.o_mode = fopen32.o_mode;
			fopen.o_pathname = CAST_USER_ADDR_T(fopen32.o_pathname);
		}
		if (error) {
			vnode_put(vp);
			goto outdrop;
		}
		AUDIT_ARG(fflags, fopen.o_flags);
		AUDIT_ARG(mode, fopen.o_mode);
		VATTR_INIT(&va);
		/* Mask off all but regular access permissions */
		cmode = ((fopen.o_mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
		VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

		/* Start the lookup relative to the file descriptor's vnode. */
		NDINIT(&nd, LOOKUP, OP_OPEN, USEDVP | FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
		       fopen.o_pathname, &context);
		nd.ni_dvp = vp;

		error = open1(&context, &nd, fopen.o_flags, &va,
			      fileproc_alloc_init, NULL, retval);

		vnode_put(vp);
		break;
	}
	/*
	 * SPI (private) for unlinking a file starting from a dir fd
	 */
	case F_UNLINKFROM: {
		user_addr_t pathname;

		/* Check if this isn't a valid file descriptor */
		if ((fp->f_type != DTYPE_VNODE) ||
		    (fp->f_flag & FREAD) == 0) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}
		
		/* Only valid for directories */
		if (vp->v_type != VDIR) {
			vnode_put(vp);
			error = ENOTDIR;
			goto outdrop;
		}

		/* Get flags, mode and pathname arguments. */
		if (IS_64BIT_PROCESS(p)) {
			pathname = (user_addr_t)argp;
		} else {
			pathname = CAST_USER_ADDR_T(argp);
		}

		/* Start the lookup relative to the file descriptor's vnode. */
		error = unlink1(&context, vp, pathname, UIO_USERSPACE, 0);
		
		vnode_put(vp);
		break;

	}

	case F_ADDSIGS:
	case F_ADDFILESIGS:
	case F_ADDFILESIGS_FOR_DYLD_SIM:
	case F_ADDFILESIGS_RETURN:
	{
		struct cs_blob *blob = NULL;
		struct user_fsignatures fs;
		kern_return_t kr;
		vm_offset_t kernel_blob_addr;
		vm_size_t kernel_blob_size;
		int blob_add_flags = 0;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if (uap->cmd == F_ADDFILESIGS_FOR_DYLD_SIM) {
			blob_add_flags |= MAC_VNODE_CHECK_DYLD_SIM;
			if ((p->p_csflags & CS_KILL) == 0) {
				proc_lock(p);
				p->p_csflags |= CS_KILL;
				proc_unlock(p);
			}
		}

		error = vnode_getwithref(vp);
		if (error)
			goto outdrop;

		if (IS_64BIT_PROCESS(p)) {
			error = copyin(argp, &fs, sizeof (fs));
		} else {
			struct user32_fsignatures fs32;

			error = copyin(argp, &fs32, sizeof (fs32));
			fs.fs_file_start = fs32.fs_file_start;
			fs.fs_blob_start = CAST_USER_ADDR_T(fs32.fs_blob_start);
			fs.fs_blob_size = fs32.fs_blob_size;
		}

		if (error) {
			vnode_put(vp);
			goto outdrop;
		}

		/*
		 * First check if we have something loaded a this offset
		 */
		blob = ubc_cs_blob_get(vp, CPU_TYPE_ANY, fs.fs_file_start);
		if (blob != NULL)
		{
			/* If this is for dyld_sim revalidate the blob */
			if (uap->cmd == F_ADDFILESIGS_FOR_DYLD_SIM) {
				error = ubc_cs_blob_revalidate(vp, blob, blob_add_flags);
			}

		} else {
			/*
			 * An arbitrary limit, to prevent someone from mapping in a 20GB blob.  This should cover
			 * our use cases for the immediate future, but note that at the time of this commit, some
			 * platforms are nearing 2MB blob sizes (with a prior soft limit of 2.5MB).
			 *
			 * We should consider how we can manage this more effectively; the above means that some
			 * platforms are using megabytes of memory for signing data; it merely hasn't crossed the
			 * threshold considered ridiculous at the time of this change.
			 */
#define CS_MAX_BLOB_SIZE (40ULL * 1024ULL * 1024ULL)
			if (fs.fs_blob_size > CS_MAX_BLOB_SIZE) {
				error = E2BIG;
				vnode_put(vp);
				goto outdrop;
			}

			kernel_blob_size = CAST_DOWN(vm_size_t, fs.fs_blob_size);
			kr = ubc_cs_blob_allocate(&kernel_blob_addr, &kernel_blob_size);
			if (kr != KERN_SUCCESS) {
				error = ENOMEM;
				vnode_put(vp);
				goto outdrop;
			}

			if(uap->cmd == F_ADDSIGS) {
				error = copyin(fs.fs_blob_start,
					       (void *) kernel_blob_addr,
					       kernel_blob_size);
			} else /* F_ADDFILESIGS || F_ADDFILESIGS_RETURN || F_ADDFILESIGS_FOR_DYLD_SIM */ {
				int resid;

				error = vn_rdwr(UIO_READ,
						vp,
						(caddr_t) kernel_blob_addr,
						kernel_blob_size,
						fs.fs_file_start + fs.fs_blob_start,
						UIO_SYSSPACE,
						0,
						kauth_cred_get(),
						&resid,
						p);
				if ((error == 0) && resid) {
					/* kernel_blob_size rounded to a page size, but signature may be at end of file */
					memset((void *)(kernel_blob_addr + (kernel_blob_size - resid)), 0x0, resid);
				}
			}
		
			if (error) {
				ubc_cs_blob_deallocate(kernel_blob_addr,
						       kernel_blob_size);
				vnode_put(vp);
				goto outdrop;
			}

			blob = NULL;
			error = ubc_cs_blob_add(vp,
						CPU_TYPE_ANY,	/* not for a specific architecture */
						fs.fs_file_start,
						kernel_blob_addr,
						kernel_blob_size,
						blob_add_flags,
						&blob);
			if (error) {
				ubc_cs_blob_deallocate(kernel_blob_addr,
						       kernel_blob_size);
			} else {
				/* ubc_blob_add() has consumed "kernel_blob_addr" */
#if CHECK_CS_VALIDATION_BITMAP
				ubc_cs_validation_bitmap_allocate( vp );
#endif
			}
		}

		if (uap->cmd == F_ADDFILESIGS_RETURN || uap->cmd == F_ADDFILESIGS_FOR_DYLD_SIM) {
			/*
			 * The first element of the structure is a
			 * off_t that happen to have the same size for
			 * all archs. Lets overwrite that.
			 */
			off_t end_offset = 0;
			if (blob)
				end_offset = blob->csb_end_offset;
			error = copyout(&end_offset, argp, sizeof (end_offset));
		}

		(void) vnode_put(vp);
		break;
	}
	case F_FINDSIGS: {
		error = ENOTSUP;
		goto out;
	}
#if CONFIG_PROTECT
	case F_GETPROTECTIONCLASS: {
		int class = 0;
		
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		proc_fdunlock(p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}
	
		error = cp_vnode_getclass (vp, &class);
		if (error == 0) {
			*retval = class;
		}

		vnode_put(vp);
		break;
	}
	
	case F_SETPROTECTIONCLASS: {
		/* tmp must be a valid PROTECTION_CLASS_* */
		tmp = CAST_DOWN_EXPLICIT(uint32_t, uap->arg);
		
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		proc_fdunlock(p);
	
		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}	
		
		/* Only go forward if you have write access */
		vfs_context_t ctx = vfs_context_current();
		if(vnode_authorize(vp, NULLVP, (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), ctx) != 0) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}
		error = cp_vnode_setclass (vp, tmp);
		vnode_put(vp);
		break;
	}	

	case F_TRANSCODEKEY: {
		
		char *backup_keyp = NULL;
		unsigned backup_key_len = CP_MAX_WRAPPEDKEYSIZE;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}	

		MALLOC(backup_keyp, char *, backup_key_len, M_TEMP, M_WAITOK);
		if (backup_keyp == NULL) {
			error = ENOMEM;
			goto outdrop;
		}

		error = cp_vnode_transcode (vp, backup_keyp, &backup_key_len);
		vnode_put(vp);

		if (error == 0) {
			error = copyout((caddr_t)backup_keyp, argp, backup_key_len);
			*retval = backup_key_len;
		}

		FREE(backup_keyp, M_TEMP);

		break;
	}	

	case F_GETPROTECTIONLEVEL:  {
		uint32_t cp_version = 0;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF; 
			goto out;
		}

		vp = (struct vnode*) fp->f_data;
		proc_fdunlock (p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}

		/*
		 * if cp_get_major_vers fails, error will be set to proper errno 
		 * and cp_version will still be 0.
		 */

		error = cp_get_root_major_vers (vp, &cp_version);
		*retval = cp_version;

		vnode_put (vp);
		break;
	}

	case F_GETDEFAULTPROTLEVEL:  {
		uint32_t cp_default = 0;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF; 
			goto out;
		}

		vp = (struct vnode*) fp->f_data;
		proc_fdunlock (p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}

		/*
		 * if cp_get_major_vers fails, error will be set to proper errno 
		 * and cp_version will still be 0.
		 */

		error = cp_get_default_level(vp, &cp_default);
		*retval = cp_default;

		vnode_put (vp);
		break;
	}

	
#endif /* CONFIG_PROTECT */

	case F_MOVEDATAEXTENTS: {
		struct fileproc *fp2 = NULL;
		struct vnode *src_vp = NULLVP;
		struct vnode *dst_vp = NULLVP;
		/* We need to grab the 2nd FD out of the argments before moving on. */
		int fd2 = CAST_DOWN_EXPLICIT(int32_t, uap->arg);

		error = priv_check_cred(kauth_cred_get(), PRIV_VFS_MOVE_DATA_EXTENTS, 0);
		if (error)
			goto out;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}

		/* For now, special case HFS+ only, since this is SPI. */
		src_vp = (struct vnode *)fp->f_data;
		if (src_vp->v_tag != VT_HFS) {
			error = EINVAL;
			goto out;
		}

		/*
		 * Get the references before we start acquiring iocounts on the vnodes, 
		 * while we still hold the proc fd lock
		 */
		if ( (error = fp_lookup(p, fd2, &fp2, 1)) ) {
			error = EBADF;
			goto out;
		}
		if (fp2->f_type != DTYPE_VNODE) {
			fp_drop(p, fd2, fp2, 1);
			error = EBADF;
			goto out;
		}
		dst_vp = (struct vnode *)fp2->f_data;
		if (dst_vp->v_tag != VT_HFS) {
			fp_drop(p, fd2, fp2, 1);
			error = EINVAL;
			goto out;
		}

#if CONFIG_MACF
		/* Re-do MAC checks against the new FD, pass in a fake argument */
		error = mac_file_check_fcntl(proc_ucred(p), fp2->f_fglob, uap->cmd, 0);
		if (error) {
			fp_drop(p, fd2, fp2, 1);
			goto out;
		}
#endif
		/* Audit the 2nd FD */
		AUDIT_ARG(fd, fd2);

		proc_fdunlock(p);

		if (vnode_getwithref(src_vp)) {
			fp_drop(p, fd2, fp2, 0);
			error = ENOENT;
			goto outdrop;
		}	
		if (vnode_getwithref(dst_vp)) {
			vnode_put (src_vp);
			fp_drop(p, fd2, fp2, 0);
			error = ENOENT;
			goto outdrop;
		}	
		
		/* 
		 * Basic asserts; validate they are not the same and that
		 * both live on the same filesystem.
		 */
		if (dst_vp == src_vp) {
			vnode_put (src_vp);
			vnode_put (dst_vp);
			fp_drop (p, fd2, fp2, 0);
			error = EINVAL;
			goto outdrop;
		}	

		if (dst_vp->v_mount != src_vp->v_mount) {
			vnode_put (src_vp);
			vnode_put (dst_vp);
			fp_drop (p, fd2, fp2, 0);
			error = EXDEV;
			goto outdrop;
		}

		/* Now we have a legit pair of FDs.  Go to work */

		/* Now check for write access to the target files */
		if(vnode_authorize(src_vp, NULLVP, 
						   (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), &context) != 0) {
			vnode_put(src_vp);
			vnode_put(dst_vp);
			fp_drop(p, fd2, fp2, 0);
			error = EBADF;
			goto outdrop;
		}
		
		if(vnode_authorize(dst_vp, NULLVP, 
						   (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), &context) != 0) {
			vnode_put(src_vp);
			vnode_put(dst_vp);
			fp_drop(p, fd2, fp2, 0);
			error = EBADF;
			goto outdrop;
		}
			
		/* Verify that both vps point to files and not directories */
		if ( !vnode_isreg(src_vp) || !vnode_isreg(dst_vp)) {
			error = EINVAL;
			vnode_put (src_vp);
			vnode_put (dst_vp);
			fp_drop (p, fd2, fp2, 0);
			goto outdrop;
		}

		/* 
		 * The exchangedata syscall handler passes in 0 for the flags to VNOP_EXCHANGE.
		 * We'll pass in our special bit indicating that the new behavior is expected
		 */
		
		error = VNOP_EXCHANGE(src_vp, dst_vp, FSOPT_EXCHANGE_DATA_ONLY, &context);
		
		vnode_put (src_vp);
		vnode_put (dst_vp);
		fp_drop(p, fd2, fp2, 0);
		break;
	}
	
	/* 
	 * SPI for making a file compressed.
	 */
	case F_MAKECOMPRESSED: {
		uint32_t gcounter = CAST_DOWN_EXPLICIT(uint32_t, uap->arg);

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF; 
			goto out;
		}

		vp = (struct vnode*) fp->f_data;
		proc_fdunlock (p);

		/* get the vnode */
		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}

		/* Is it a file? */
		if ((vnode_isreg(vp) == 0) && (vnode_islnk(vp) == 0)) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}

		/* invoke ioctl to pass off to FS */
		/* Only go forward if you have write access */ 
		vfs_context_t ctx = vfs_context_current();
		if(vnode_authorize(vp, NULLVP, (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), ctx) != 0) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}

		error = VNOP_IOCTL(vp, uap->cmd, (caddr_t)&gcounter, 0, &context);

		vnode_put (vp);
		break;				   
	}
			
	/*
	 * SPI (private) for indicating to a filesystem that subsequent writes to
	 * the open FD will written to the Fastflow.
	 */
	case F_SET_GREEDY_MODE:
		/* intentionally drop through to the same handler as F_SETSTATIC.
		 * both fcntls should pass the argument and their selector into VNOP_IOCTL.
		 */

	/*
	 * SPI (private) for indicating to a filesystem that subsequent writes to
	 * the open FD will represent static content.
	 */
	case F_SETSTATICCONTENT: {
		caddr_t ioctl_arg = NULL;

		if (uap->arg) {
			ioctl_arg = (caddr_t) 1;
		}

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		error = vnode_getwithref(vp);
		if (error) {
			error = ENOENT;
			goto outdrop;
		}

		/* Only go forward if you have write access */
		vfs_context_t ctx = vfs_context_current();
		if(vnode_authorize(vp, NULLVP, (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), ctx) != 0) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}

		error = VNOP_IOCTL(vp, uap->cmd, ioctl_arg, 0, &context);
		(void)vnode_put(vp);
	
		break;
	}

	/*
	 * SPI (private) for indicating to the lower level storage driver that the
	 * subsequent writes should be of a particular IO type (burst, greedy, static),
	 * or other flavors that may be necessary.
	 */
	case F_SETIOTYPE: {
		caddr_t param_ptr; 
		uint32_t param;

		if (uap->arg) {
			/* extract 32 bits of flags from userland */
			param_ptr = (caddr_t) uap->arg;
			param = (uint32_t) param_ptr;
		}
		else {
			/* If no argument is specified, error out */
			error = EINVAL;
			goto out;
		}
		
		/* 
		 * Validate the different types of flags that can be specified: 
		 * all of them are mutually exclusive for now.
		 */
		switch (param) {
			case F_IOTYPE_ISOCHRONOUS:
				break;

			default:
				error = EINVAL;
				goto out;
		}


		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		error = vnode_getwithref(vp);
		if (error) {
			error = ENOENT;
			goto outdrop;
		}

		/* Only go forward if you have write access */
		vfs_context_t ctx = vfs_context_current();
		if(vnode_authorize(vp, NULLVP, (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), ctx) != 0) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}

		error = VNOP_IOCTL(vp, uap->cmd, param_ptr, 0, &context);
		(void)vnode_put(vp);

		break;
	}

	
	/*
	 * Extract the CodeDirectory of the vnode associated with
	 * the file descriptor and copy it back to user space
	 */
	case F_GETCODEDIR: {
		struct user_fcodeblobs args;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}

		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ((fp->f_flag & FREAD) == 0) {
			error = EBADF;
			goto outdrop;
		}

		if (IS_64BIT_PROCESS(p)) {
			struct user64_fcodeblobs args64;

			error = copyin(argp, &args64, sizeof(args64));
			if (error) 
				goto outdrop;

			args.f_cd_hash = args64.f_cd_hash;
			args.f_hash_size = args64.f_hash_size;
			args.f_cd_buffer = args64.f_cd_buffer;
			args.f_cd_size = args64.f_cd_size;
			args.f_out_size = args64.f_out_size;
			args.f_arch = args64.f_arch;
		} else {
			struct user32_fcodeblobs args32;

			error = copyin(argp, &args32, sizeof(args32));
			if (error)
				goto outdrop;

			args.f_cd_hash = CAST_USER_ADDR_T(args32.f_cd_hash);
			args.f_hash_size = args32.f_hash_size;
			args.f_cd_buffer = CAST_USER_ADDR_T(args32.f_cd_buffer);
			args.f_cd_size = args32.f_cd_size;
			args.f_out_size = CAST_USER_ADDR_T(args32.f_out_size);
			args.f_arch = args32.f_arch;
		}

		if (vp->v_ubcinfo == NULL) {
			error = EINVAL;
			goto outdrop;
		}

		struct cs_blob *t_blob = vp->v_ubcinfo->cs_blobs;

		/*
		 * This call fails if there is no cs_blob corresponding to the
		 * vnode, or if there are multiple cs_blobs present, and the caller
		 * did not specify which cpu_type they want the cs_blob for
		 */
		if (t_blob == NULL) {
			error = ENOENT; /* there is no codesigning blob for this process */
			goto outdrop;
		} else if (args.f_arch == 0 && t_blob->csb_next != NULL) {
			error = ENOENT; /* too many architectures and none specified */
			goto outdrop;
		}

		/* If the user specified an architecture, find the right blob */
		if (args.f_arch != 0) {
			while (t_blob) {
				if (t_blob->csb_cpu_type == args.f_arch)
					break;
				t_blob = t_blob->csb_next;
			}
			/* The cpu_type the user requested could not be found */
			if (t_blob == NULL) {
				error = ENOENT;
				goto outdrop;
			}
		}

		const CS_CodeDirectory *cd = t_blob->csb_cd;
		if (cd == NULL) {
			error = ENOENT;
			goto outdrop;
		}

		uint64_t buffer_size = ntohl(cd->length);

		if (buffer_size > UINT_MAX) {
			error = ERANGE;
			goto outdrop;
		}

		error = copyout(&buffer_size, args.f_out_size, sizeof(unsigned int));
		if (error) 
			goto outdrop;

		if (sizeof(t_blob->csb_cdhash) > args.f_hash_size ||
					buffer_size > args.f_cd_size) {
			error = ERANGE;
			goto outdrop;
		}

		error = copyout(t_blob->csb_cdhash, args.f_cd_hash, sizeof(t_blob->csb_cdhash));
		if (error) 
			goto outdrop;
		error = copyout(cd, args.f_cd_buffer, buffer_size);
		if (error) 
			goto outdrop;

		break;
	}
	
	/* 
	 * Set the vnode pointed to by 'fd'
	 * and tag it as the (potentially future) backing store
	 * for another filesystem
	 */
	case F_SETBACKINGSTORE: {
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		
		vp = (struct vnode *)fp->f_data;

		if (vp->v_tag != VT_HFS) {
			error = EINVAL;
			goto out;
		}
		proc_fdunlock(p);

		if (vnode_getwithref(vp)) {
			error = ENOENT;
			goto outdrop;
		}
		
		/* only proceed if you have write access */
		vfs_context_t ctx = vfs_context_current();
		if(vnode_authorize(vp, NULLVP, (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA), ctx) != 0) {
			vnode_put(vp);
			error = EBADF;
			goto outdrop;
		}

		
		/* If arg != 0, set, otherwise unset */
		if (uap->arg) {
			error = VNOP_IOCTL (vp, uap->cmd, (caddr_t)1, 0, &context);
		}
		else {
			error = VNOP_IOCTL (vp, uap->cmd, (caddr_t)NULL, 0, &context);
		}
		
		vnode_put(vp);
		break;
	}

	/* 
	 * like F_GETPATH, but special semantics for
	 * the mobile time machine handler.
	 */
	case F_GETPATH_MTMINFO: {
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
			int backingstore = 0;
			
			/* Check for error from vn_getpath before moving on */
			if ((error = vn_getpath(vp, pathbufp, &pathlen)) == 0) {
				if (vp->v_tag == VT_HFS) {
					error = VNOP_IOCTL (vp, uap->cmd, (caddr_t) &backingstore, 0, &context);
				}
				(void)vnode_put(vp);

				if (error == 0) {
					error = copyout((caddr_t)pathbufp, argp, pathlen);
				}
				if (error == 0) {
					/* 
					 * If the copyout was successful, now check to ensure
					 * that this vnode is not a BACKINGSTORE vnode.  mtmd
					 * wants the path regardless.
					 */
					if (backingstore) {
						error = EBUSY;
					}
				}
			} else
				(void)vnode_put(vp);
		}
		FREE(pathbufp, M_TEMP);
		goto outdrop;
	}

#if DEBUG || DEVELOPMENT
	case F_RECYCLE:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		vnode_recycle(vp);
		break;
#endif

	default:
		/*
		 * This is an fcntl() that we d not recognize at this level;
		 * if this is a vnode, we send it down into the VNOP_IOCTL
		 * for this vnode; this can include special devices, and will
		 * effectively overload fcntl() to send ioctl()'s.
		 */
		if((uap->cmd & IOC_VOID) && (uap->cmd & IOC_INOUT)){
            error = EINVAL;
			goto out;
		}
		
		/* Catch any now-invalid fcntl() selectors */
		switch (uap->cmd) {
			case F_MARKDEPENDENCY:
				error = EINVAL;
				goto out;
			default:
				break;
		}

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {
#define STK_PARAMS 128
			char stkbuf[STK_PARAMS];
			unsigned int size;
			caddr_t data, memp;
			/*
			 * For this to work properly, we have to copy in the
			 * ioctl() cmd argument if there is one; we must also
			 * check that a command parameter, if present, does
			 * not exceed the maximum command length dictated by
			 * the number of bits we have available in the command
			 * to represent a structure length.  Finally, we have
			 * to copy the results back out, if it is that type of
			 * ioctl().
			 */
			size = IOCPARM_LEN(uap->cmd);
			if (size > IOCPARM_MAX) {
				(void)vnode_put(vp);
				error = EINVAL;
				break;
			}

			memp = NULL;
			if (size > sizeof (stkbuf)) {
				if ((memp = (caddr_t)kalloc(size)) == 0) {
					(void)vnode_put(vp);
					error = ENOMEM;
					goto outdrop;
				}
				data = memp;
			} else {
				data = &stkbuf[0];
			}
			
			if (uap->cmd & IOC_IN) {
				if (size) {
					/* structure */
					error = copyin(argp, data, size);
					if (error) {
						(void)vnode_put(vp);
						if (memp)
							kfree(memp, size);
						goto outdrop;
					}

					/* Bzero the section beyond that which was needed */
					if (size <= sizeof(stkbuf)) {
						bzero ( (((uint8_t*)data) + size), (sizeof(stkbuf) - size));
					}
				} else {
					/* int */
					if (is64bit) {
						*(user_addr_t *)data = argp;
					} else {
						*(uint32_t *)data = (uint32_t)argp;
					}
				};
			} else if ((uap->cmd & IOC_OUT) && size) {
				/*
				 * Zero the buffer so the user always
				 * gets back something deterministic.
				 */
				bzero(data, size);
			} else if (uap->cmd & IOC_VOID) {
				if (is64bit) {
				    *(user_addr_t *)data = argp;
				} else {
				    *(uint32_t *)data = (uint32_t)argp;
				}
			}

			error = VNOP_IOCTL(vp, uap->cmd, CAST_DOWN(caddr_t, data), 0, &context);

			(void)vnode_put(vp);

			/* Copy any output data to user */
			if (error == 0 && (uap->cmd & IOC_OUT) && size) 
				error = copyout(data, argp, size);
			if (memp)
				kfree(memp, size);
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
 * finishdup
 *
 * Description:	Common code for dup, dup2, and fcntl(F_DUPFD).
 *
 * Parameters:	p				Process performing the dup
 *		old				The fd to dup
 *		new				The fd to dup it to
 *		fd_flags			Flags to augment the new fd
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		EBADF
 *		ENOMEM
 *
 * Implicit returns:
 *		*retval (modified)		The new descriptor
 *
 * Locks:	Assumes proc_fdlock for process pointing to fdp is held by
 *		the caller
 *
 * Notes:	This function may drop and reacquire this lock; it is unsafe
 *		for a caller to assume that other state protected by the lock
 *		has not been subsequently changed out from under it.
 */
int
finishdup(proc_t p,
    struct filedesc *fdp, int old, int new, int fd_flags, int32_t *retval)
{
	struct fileproc *nfp;
	struct fileproc *ofp;
#if CONFIG_MACF
	int error;
#endif

#if DIAGNOSTIC
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif
	if ((ofp = fdp->fd_ofiles[old]) == NULL ||
	    (fdp->fd_ofileflags[old] & UF_RESERVED)) {
		fdrelse(p, new);
		return (EBADF);
	}
	fg_ref(ofp);

#if CONFIG_MACF
	error = mac_file_check_dup(proc_ucred(p), ofp->f_fglob, new);
	if (error) {
		fg_drop(ofp);
		fdrelse(p, new);
		return (error);
	}
#endif

	proc_fdunlock(p);

	nfp = fileproc_alloc_init(NULL);

	proc_fdlock(p);

	if (nfp == NULL) {
		fg_drop(ofp);
		fdrelse(p, new);
		return (ENOMEM);
	}

	nfp->f_fglob = ofp->f_fglob;

#if DIAGNOSTIC
	if (fdp->fd_ofiles[new] != 0)
		panic("finishdup: overwriting fd_ofiles with new %d", new);
	if ((fdp->fd_ofileflags[new] & UF_RESERVED) == 0)
		panic("finishdup: unreserved fileflags with new %d", new);
#endif

	if (new > fdp->fd_lastfile)
		fdp->fd_lastfile = new;
	*fdflags(p, new) |= fd_flags;
	procfdtbl_releasefd(p, new, nfp);
	*retval = new;
	return (0);
}


/*
 * close
 *
 * Description:	The implementation of the close(2) system call
 *
 * Parameters:	p			Process in whose per process file table
 *					the close is to occur
 *		uap->fd			fd to be closed
 *		retval			<unused>
 *
 * Returns:	0			Success
 *	fp_lookup:EBADF			Bad file descriptor
 *      fp_guard_exception:???          Guarded file descriptor
 *	close_internal:EBADF
 *	close_internal:??? 		Anything returnable by a per-fileops
 *					close function
 */
int
close(proc_t p, struct close_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(close_nocancel(p, (struct close_nocancel_args *)uap, retval));
}


int
close_nocancel(proc_t p, struct close_nocancel_args *uap, __unused int32_t *retval)
{
	struct fileproc *fp;
	int fd = uap->fd;
	int error;

	AUDIT_SYSCLOSE(p, fd);

	proc_fdlock(p);

	if ( (error = fp_lookup(p,fd,&fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}

	if (FP_ISGUARDED(fp, GUARD_CLOSE)) {
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_CLOSE);
		(void) fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);
		return (error);
	}

	error = close_internal_locked(p, fd, fp, 0);

	proc_fdunlock(p);

	return (error);
}


/*
 * close_internal_locked
 *
 * Close a file descriptor.
 *
 * Parameters:	p			Process in whose per process file table
 *					the close is to occur
 *		fd			fd to be closed
 *		fp			fileproc associated with the fd
 *
 * Returns:	0			Success
 *		EBADF			fd already in close wait state
 *	closef_locked:??? 		Anything returnable by a per-fileops
 *					close function
 *
 * Locks:	Assumes proc_fdlock for process is held by the caller and returns
 *		with lock held
 *
 * Notes:	This function may drop and reacquire this lock; it is unsafe
 *		for a caller to assume that other state protected by the lock
 *		has not been subsequently changed out from under it.
 */
int
close_internal_locked(proc_t p, int fd, struct fileproc *fp, int flags)
{
	struct filedesc *fdp = p->p_fd;
	int error =0;
	int resvfd = flags & FD_DUP2RESV;


#if DIAGNOSTIC
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif

	/* Keep people from using the filedesc while we are closing it */
	procfdtbl_markclosefd(p, fd);


	if ((fp->f_flags & FP_CLOSING) == FP_CLOSING) {
		panic("close_internal_locked: being called on already closing fd");
	}


#if DIAGNOSTIC
	if ((fdp->fd_ofileflags[fd] & UF_RESERVED) == 0)
		panic("close_internal: unreserved fileflags with fd %d", fd);
#endif

	fp->f_flags |= FP_CLOSING;

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

	fileproc_drain(p, fp);

	if (resvfd == 0) {
		_fdrelse(p, fd);
	} else {
		procfdtbl_reservefd(p, fd);
	}

	if (ENTR_SHOULDTRACE && fp->f_type == DTYPE_SOCKET)
		KERNEL_ENERGYTRACE(kEnTrActKernSocket, DBG_FUNC_END,
		    fd, 0, (int64_t)VM_KERNEL_ADDRPERM(fp->f_data));

	error = closef_locked(fp, fp->f_fglob, p);
	if ((fp->f_flags & FP_WAITCLOSE) == FP_WAITCLOSE)
		wakeup(&fp->f_flags);
	fp->f_flags &= ~(FP_WAITCLOSE | FP_CLOSING);

	proc_fdunlock(p);

	fileproc_free(fp);	

	proc_fdlock(p);

#if DIAGNOSTIC
	if (resvfd != 0) {
		if ((fdp->fd_ofileflags[fd] & UF_RESERVED) == 0)
			panic("close with reserved fd returns with freed fd:%d: proc: %p", fd, p);
	}
#endif

	return(error);
}


/*
 * fstat1
 *
 * Description:	Return status information about a file descriptor.
 *
 * Parameters:	p				The process doing the fstat
 *		fd				The fd to stat
 *		ub				The user stat buffer
 *		xsecurity			The user extended security
 *						buffer, or 0 if none
 *		xsecurity_size			The size of xsecurity, or 0
 *						if no xsecurity
 *		isstat64			Flag to indicate 64 bit version
 *						for inode size, etc.
 *
 * Returns:	0				Success
 *		EBADF
 *		EFAULT
 *	fp_lookup:EBADF				Bad file descriptor
 *	vnode_getwithref:???
 *	copyout:EFAULT
 *	vnode_getwithref:???
 *	vn_stat:???
 *	soo_stat:???
 *	pipe_stat:???
 *	pshm_stat:???
 *	kqueue_stat:???
 *
 * Notes:	Internal implementation for all other fstat() related
 *		functions
 *
 *		XXX switch on node type is bogus; need a stat in struct
 *		XXX fileops instead.
 */
static int
fstat1(proc_t p, int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size, int isstat64)
{
	struct fileproc *fp;
	union {
		struct stat sb;
		struct stat64 sb64;
	} source;
	union {
		struct user64_stat user64_sb;
		struct user32_stat user32_sb;
		struct user64_stat64 user64_sb64;
		struct user32_stat64 user32_sb64;
	} dest;
	int error, my_size;
	file_type_t type;
	caddr_t data;
	kauth_filesec_t fsec;
	user_size_t xsecurity_bufsize;
	vfs_context_t ctx = vfs_context_current();
	void * sbptr;


	AUDIT_ARG(fd, fd);

	if ((error = fp_lookup(p, fd, &fp, 0)) != 0) {
		return(error);
	}
	type = fp->f_type;
	data = fp->f_data;
	fsec = KAUTH_FILESEC_NONE;

	sbptr = (void *)&source;

	switch (type) {

	case DTYPE_VNODE:
		if ((error = vnode_getwithref((vnode_t)data)) == 0) {
			/*
			 * If the caller has the file open, and is not
			 * requesting extended security information, we are
			 * going to let them get the basic stat information.
			 */
			if (xsecurity == USER_ADDR_NULL) {
				error = vn_stat_noauth((vnode_t)data, sbptr, NULL, isstat64, ctx);
			} else {
				error = vn_stat((vnode_t)data, sbptr, &fsec, isstat64, ctx);
			}

			AUDIT_ARG(vnpath, (struct vnode *)data, ARG_VNODE1);
			(void)vnode_put((vnode_t)data);
		}
		break;

#if SOCKETS
	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)data, sbptr, isstat64);
		break;
#endif /* SOCKETS */

	case DTYPE_PIPE:
		error = pipe_stat((void *)data, sbptr, isstat64);
		break;

	case DTYPE_PSXSHM:
		error = pshm_stat((void *)data, sbptr, isstat64);
		break;

	case DTYPE_KQUEUE:
		error = kqueue_stat((void *)data, sbptr, isstat64, p);
		break;

	default:
		error = EBADF;
		goto out;
	}
	if (error == 0) {
		caddr_t sbp;

		if (isstat64 != 0) {
			source.sb64.st_lspare = 0;
			source.sb64.st_qspare[0] = 0LL;
			source.sb64.st_qspare[1] = 0LL;

			if (IS_64BIT_PROCESS(current_proc())) {
				munge_user64_stat64(&source.sb64, &dest.user64_sb64); 
				my_size = sizeof(dest.user64_sb64);
				sbp = (caddr_t)&dest.user64_sb64;
			} else {
				munge_user32_stat64(&source.sb64, &dest.user32_sb64); 
				my_size = sizeof(dest.user32_sb64);
				sbp = (caddr_t)&dest.user32_sb64;
			}
		} else {
			source.sb.st_lspare = 0;
			source.sb.st_qspare[0] = 0LL;
			source.sb.st_qspare[1] = 0LL;
			if (IS_64BIT_PROCESS(current_proc())) {
				munge_user64_stat(&source.sb, &dest.user64_sb); 
				my_size = sizeof(dest.user64_sb);
				sbp = (caddr_t)&dest.user64_sb;
			} else {
				munge_user32_stat(&source.sb, &dest.user32_sb); 
				my_size = sizeof(dest.user32_sb);
				sbp = (caddr_t)&dest.user32_sb;
			}
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


/*
 * fstat_extended
 *
 * Description:	Extended version of fstat supporting returning extended
 *		security information
 *
 * Parameters:	p				The process doing the fstat
 *		uap->fd				The fd to stat
 *		uap->ub				The user stat buffer
 *		uap->xsecurity			The user extended security
 *						buffer, or 0 if none
 *		uap->xsecurity_size		The size of xsecurity, or 0
 *
 * Returns:	0				Success
 *		!0				Errno (see fstat1)
 */
int
fstat_extended(proc_t p, struct fstat_extended_args *uap, __unused int32_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, uap->xsecurity, uap->xsecurity_size, 0));
}
 

/*
 * fstat
 *
 * Description:	Get file status for the file associated with fd
 *
 * Parameters:	p				The process doing the fstat
 *		uap->fd				The fd to stat
 *		uap->ub				The user stat buffer
 *
 * Returns:	0				Success
 *		!0				Errno (see fstat1)
 */
int
fstat(proc_t p, register struct fstat_args *uap, __unused int32_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, 0, 0, 0));
}


/*
 * fstat64_extended
 *
 * Description:	Extended version of fstat64 supporting returning extended
 *		security information
 *
 * Parameters:	p				The process doing the fstat
 *		uap->fd				The fd to stat
 *		uap->ub				The user stat buffer
 *		uap->xsecurity			The user extended security
 *						buffer, or 0 if none
 *		uap->xsecurity_size		The size of xsecurity, or 0
 *
 * Returns:	0				Success
 *		!0				Errno (see fstat1)
 */
int
fstat64_extended(proc_t p, struct fstat64_extended_args *uap, __unused int32_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, uap->xsecurity, uap->xsecurity_size, 1));
}
 

/*
 * fstat64
 *
 * Description:	Get 64 bit version of the file status for the file associated
 *		with fd
 *
 * Parameters:	p				The process doing the fstat
 *		uap->fd				The fd to stat
 *		uap->ub				The user stat buffer
 *
 * Returns:	0				Success
 *		!0				Errno (see fstat1)
 */
int
fstat64(proc_t p, register struct fstat64_args *uap, __unused int32_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, 0, 0, 1));
}


/*
 * fpathconf
 *
 * Description:	Return pathconf information about a file descriptor.
 *
 * Parameters:	p				Process making the request
 *		uap->fd				fd to get information about
 *		uap->name			Name of information desired
 *		retval				Pointer to the call return area
 *
 * Returns:	0				Success
 *		EINVAL
 *	fp_lookup:EBADF				Bad file descriptor
 *	vnode_getwithref:???
 *	vn_pathconf:???
 *
 * Implicit returns:
 *		*retval (modified)		Returned information (numeric)
 */
int
fpathconf(proc_t p, struct fpathconf_args *uap, int32_t *retval)
{
	int fd = uap->fd;
	struct fileproc *fp;
	struct vnode *vp;
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
		if (uap->name != _PC_PIPE_BUF) {
			error = EINVAL;
			goto out;
		}
		*retval = PIPE_BUF;
		error = 0;
		goto out;

	case DTYPE_VNODE:
		vp = (struct vnode *)data;

		if ( (error = vnode_getwithref(vp)) == 0) {
		        AUDIT_ARG(vnpath, vp, ARG_VNODE1);

			error = vn_pathconf(vp, uap->name, retval, vfs_context_current());

			(void)vnode_put(vp);
		}
		goto out;

	default:
		error = EINVAL;
		goto out;

	}
	/*NOTREACHED*/
out:
	fp_drop(p, fd, fp, 0);
	return(error);
}

/*
 * Statistics counter for the number of times a process calling fdalloc()
 * has resulted in an expansion of the per process open file table.
 *
 * XXX This would likely be of more use if it were per process
 */
int fdexpand;


/*
 * fdalloc
 *
 * Description:	Allocate a file descriptor for the process.
 *
 * Parameters:	p				Process to allocate the fd in
 *		want				The fd we would prefer to get
 *		result				Pointer to fd we got
 *
 * Returns:	0				Success
 *		EMFILE
 *		ENOMEM
 *
 * Implicit returns:
 *		*result (modified)		The fd which was allocated
 */
int
fdalloc(proc_t p, int want, int *result)
{
	struct filedesc *fdp = p->p_fd;
	int i;
	int lim, last, numfiles, oldnfiles;
	struct fileproc **newofiles, **ofiles;
	char *newofileflags;

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 */
#if DIAGNOSTIC
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);
#endif

	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	for (;;) {
		last = min(fdp->fd_nfiles, lim);
		if ((i = want) < fdp->fd_freefile)
			i = fdp->fd_freefile;
		for (; i < last; i++) {
			if (fdp->fd_ofiles[i] == NULL && !(fdp->fd_ofileflags[i] & UF_RESERVED)) {
				procfdtbl_reservefd(p, i);
				if (i > fdp->fd_lastfile)
					fdp->fd_lastfile = i;
				if (want <= fdp->fd_freefile)
					fdp->fd_freefile = i;
				*result = i;
				return (0);
			}
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
				oldnfiles * sizeof(*fdp->fd_ofiles));
		(void) memset(&newofiles[oldnfiles], 0,
				(numfiles - oldnfiles) * sizeof(*fdp->fd_ofiles));

		(void) memcpy(newofileflags, fdp->fd_ofileflags,
				oldnfiles * sizeof(*fdp->fd_ofileflags));
		(void) memset(&newofileflags[oldnfiles], 0,
				(numfiles - oldnfiles) *
						sizeof(*fdp->fd_ofileflags));
		ofiles = fdp->fd_ofiles;
		fdp->fd_ofiles = newofiles;
		fdp->fd_ofileflags = newofileflags;
		fdp->fd_nfiles = numfiles;
		FREE_ZONE(ofiles, oldnfiles * OFILESIZE, M_OFILETABL);
		fdexpand++;
	}
}


/*
 * fdavail
 *
 * Description:	Check to see whether n user file descriptors are available
 *		to the process p.
 *
 * Parameters:	p				Process to check in
 *		n				The number of fd's desired
 *
 * Returns:	0				No
 *		1				Yes
 *
 * Locks:	Assumes proc_fdlock for process is held by the caller
 *
 * Notes:	The answer only remains valid so long as the proc_fdlock is
 *		held by the caller.
 */
int
fdavail(proc_t p, int n)
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


/*
 * fdrelse
 *
 * Description:	Legacy KPI wrapper function for _fdrelse
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to free
 *
 * Returns:	void
 *
 * Locks:	Assumes proc_fdlock for process is held by the caller
 */
void
fdrelse(proc_t p, int fd)
{
	_fdrelse(p, fd);
}


/*
 * fdgetf_noref
 *
 * Description:	Get the fileproc pointer for the given fd from the per process
 *		open file table without taking an explicit reference on it.
 *
 * Parameters:	p				Process containing fd
 *		fd				fd to obtain fileproc for
 *		resultfp			Pointer to pointer return area
 *
 * Returns:	0				Success
 *		EBADF
 *
 * Implicit returns:
 *		*resultfp (modified)		Pointer to fileproc pointer
 *
 * Locks:	Assumes proc_fdlock for process is held by the caller
 *
 * Notes:	Because there is no reference explicitly taken, the returned
 *		fileproc pointer is only valid so long as the proc_fdlock
 *		remains held by the caller.
 */
int
fdgetf_noref(proc_t p, int fd, struct fileproc **resultfp)
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


/*
 * fp_getfvp
 *
 * Description:	Get fileproc and vnode pointer for a given fd from the per
 *		process open file table of the specified process, and if
 *		successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultvp			Pointer to result vnode pointer
 *						area, or 0 if none
 *
 * Returns:	0				Success
 *		EBADF				Bad file descriptor
 *		ENOTSUP				fd does not refer to a vnode
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultvp (modified)		vnode pointer
 *
 * Notes:	The resultfp and resultvp fields are optional, and may be
 *		independently specified as NULL to skip returning information
 *
 * Locks:	Internally takes and releases proc_fdlock
 */
int
fp_getfvp(proc_t p, int fd, struct fileproc **resultfp, struct vnode **resultvp)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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
 * fp_getfvpandvid
 *
 * Description:	Get fileproc, vnode pointer, and vid for a given fd from the
 *		per process open file table of the specified process, and if
 *		successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultvp			Pointer to result vnode pointer
 *						area, or 0 if none
 *		vidp				Pointer to resuld vid area
 *
 * Returns:	0				Success
 *		EBADF				Bad file descriptor
 *		ENOTSUP				fd does not refer to a vnode
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultvp (modified)		vnode pointer
 *		*vidp				vid value
 *
 * Notes:	The resultfp and resultvp fields are optional, and may be
 *		independently specified as NULL to skip returning information
 *
 * Locks:	Internally takes and releases proc_fdlock
 */
int
fp_getfvpandvid(proc_t p, int fd, struct fileproc **resultfp,
		struct vnode **resultvp, uint32_t *vidp)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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
	if (vidp)
		*vidp = (uint32_t)vnode_vid((struct vnode *)fp->f_data);
	proc_fdunlock(p);

	return (0);
}


/*
 * fp_getfsock
 *
 * Description:	Get fileproc and socket pointer for a given fd from the
 *		per process open file table of the specified process, and if
 *		successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		results				Pointer to result socket
 *						pointer area, or 0 if none
 *
 * Returns:	EBADF			The file descriptor is invalid
 *		EOPNOTSUPP		The file descriptor is not a socket
 *		0			Success
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*results (modified)		socket pointer
 *
 * Notes:	EOPNOTSUPP should probably be ENOTSOCK; this function is only
 *		ever called from accept1().
 */
int
fp_getfsock(proc_t p, int fd, struct fileproc **resultfp,
	    struct socket **results)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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


/*
 * fp_getfkq
 *
 * Description:	Get fileproc and kqueue pointer for a given fd from the
 *		per process open file table of the specified process, and if
 *		successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultkq			Pointer to result kqueue
 *						pointer area, or 0 if none
 *
 * Returns:	EBADF			The file descriptor is invalid
 *		EBADF			The file descriptor is not a socket
 *		0			Success
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultkq (modified)		kqueue pointer
 *
 * Notes:	The second EBADF should probably be something else to make
 *		the error condition distinct.
 */
int
fp_getfkq(proc_t p, int fd, struct fileproc **resultfp,
	  struct kqueue **resultkq)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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


/*
 * fp_getfpshm
 *
 * Description:	Get fileproc and POSIX shared memory pointer for a given fd
 *		from the per process open file table of the specified process
 *		and if successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultpshm			Pointer to result POSIX
 *						shared memory pointer
 *						pointer area, or 0 if none
 *
 * Returns:	EBADF			The file descriptor is invalid
 *		EBADF			The file descriptor is not a POSIX
 *					shared memory area
 *		0			Success
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultpshm (modified)		POSIX shared memory pointer
 *
 * Notes:	The second EBADF should probably be something else to make
 *		the error condition distinct.
 */
int
fp_getfpshm(proc_t p, int fd, struct fileproc **resultfp,
	    struct pshmnode **resultpshm)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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


/*
 * fp_getfsem
 *
 * Description:	Get fileproc and POSIX semaphore pointer for a given fd from
 *		the per process open file table of the specified process
 *		and if successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultpsem			Pointer to result POSIX
 *						semaphore pointer area, or
 *						0 if none
 *
 * Returns:	EBADF			The file descriptor is invalid
 *		EBADF			The file descriptor is not a POSIX
 *					semaphore
 *		0			Success
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultpsem (modified)		POSIX semaphore pointer
 *
 * Notes:	The second EBADF should probably be something else to make
 *		the error condition distinct.
 *
 *		In order to support unnamed POSIX semaphores, the named
 *		POSIX semaphores will have to move out of the per-process
 *		open filetable, and into a global table that is shared with
 *		unnamed POSIX semaphores, since unnamed POSIX semaphores
 *		are typically used by declaring instances in shared memory,
 *		and there's no other way to do this without changing the
 *		underlying type, which would introduce binary compatibility
 *		issues.
 */
int
fp_getfpsem(proc_t p, int fd, struct fileproc **resultfp,
	    struct psemnode **resultpsem)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
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


/*
 * fp_getfpipe
 *
 * Description:	Get fileproc and pipe pointer for a given fd from the
 *		per process open file table of the specified process
 *		and if successful, increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		resultpipe			Pointer to result pipe
 *						pointer area, or 0 if none
 *
 * Returns:	EBADF			The file descriptor is invalid
 *		EBADF			The file descriptor is not a socket
 *		0			Success
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *		*resultpipe (modified)		pipe pointer
 *
 * Notes:	The second EBADF should probably be something else to make
 *		the error condition distinct.
 */
int
fp_getfpipe(proc_t p, int fd, struct fileproc **resultfp,
	    struct pipe **resultpipe)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock_spin(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_PIPE) {
		proc_fdunlock(p);
		return(EBADF);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (resultpipe)
		*resultpipe = (struct pipe *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}

/*
 * fp_lookup
 *
 * Description:	Get fileproc pointer for a given fd from the per process
 *		open file table of the specified process and if successful,
 *		increment the f_iocount
 *
 * Parameters:	p				Process in which fd lives
 *		fd				fd to get information for
 *		resultfp			Pointer to result fileproc
 *						pointer area, or 0 if none
 *		locked				!0 if the caller holds the
 *						proc_fdlock, 0 otherwise
 *
 * Returns:	0			Success
 *		EBADF			Bad file descriptor
 *
 * Implicit returns:
 *		*resultfp (modified)		Fileproc pointer
 *
 * Locks:	If the argument 'locked' is non-zero, then the caller is
 *		expected to have taken and held the proc_fdlock; if it is
 *		zero, than this routine internally takes and drops this lock.
 */
int
fp_lookup(proc_t p, int fd, struct fileproc **resultfp, int locked)
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	if (!locked)
		proc_fdlock_spin(p);
	if (fd < 0 || fdp == NULL || fd >= fdp->fd_nfiles ||
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


/*
 * fp_tryswap
 * 
 * Description: Swap the fileproc pointer for a given fd with a new
 *		fileproc pointer in the per-process open file table of
 *		the specified process.  The fdlock must be held at entry.
 *
 * Parameters:  p		Process containing the fd
 *		fd		The fd of interest
 *		nfp		Pointer to the newfp
 *
 * Returns:	0		Success
 *		EBADF		Bad file descriptor
 *		EINTR		Interrupted
 *		EKEEPLOOKING	f_iocount changed while lock was dropped.
 */
int
fp_tryswap(proc_t p, int fd, struct fileproc *nfp)
{
	struct fileproc *fp;
	int error;

	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);

	if (0 != (error = fp_lookup(p, fd, &fp, 1)))
		return (error);
	/*
	 * At this point, our caller (change_guardedfd_np) has
	 * one f_iocount reference, and we just took another
	 * one to begin the replacement.
	 */
	if (fp->f_iocount < 2) {
		panic("f_iocount too small %d", fp->f_iocount);
	} else if (2 == fp->f_iocount) {

		/* Copy the contents of *fp, preserving the "type" of *nfp */

		nfp->f_flags = (nfp->f_flags & FP_TYPEMASK) |
			(fp->f_flags & ~FP_TYPEMASK);
		nfp->f_iocount = fp->f_iocount;
		nfp->f_fglob = fp->f_fglob;
		nfp->f_wset = fp->f_wset;

		p->p_fd->fd_ofiles[fd] = nfp;
		(void) fp_drop(p, fd, nfp, 1);
	} else {
		/*
		 * Wait for all other active references to evaporate.
		 */
		p->p_fpdrainwait = 1;
		error = msleep(&p->p_fpdrainwait, &p->p_fdmlock,
		    PRIBIO | PCATCH, "tryswap fpdrain", NULL);
		if (0 == error) {
			/*
			 * Return an "internal" errno to trigger a full
			 * reevaluation of the change-guard attempt.
			 */
			error = EKEEPLOOKING;
			printf("%s: lookup collision fd %d\n", __func__, fd);
		}
		(void) fp_drop(p, fd, fp, 1);
	}
	return (error);
}


/*
 * fp_drop_written
 *
 * Description:	Set the FP_WRITTEN flag on the fileproc and drop the I/O
 *		reference previously taken by calling fp_lookup et. al.
 *
 * Parameters:	p				Process in which the fd lives
 *		fd				fd associated with the fileproc
 *		fp				fileproc on which to set the
 *						flag and drop the reference
 *
 * Returns:	0				Success
 *	fp_drop:EBADF				Bad file descriptor
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the supplied process
 *
 * Notes:	The fileproc must correspond to the fd in the supplied proc
 */
int
fp_drop_written(proc_t p, int fd, struct fileproc *fp)
{
        int error;

	proc_fdlock_spin(p);

	fp->f_flags |= FP_WRITTEN;
	
	error = fp_drop(p, fd, fp, 1);

	proc_fdunlock(p);
		
	return (error);
}


/*
 * fp_drop_event
 *
 * Description:	Set the FP_WAITEVENT flag on the fileproc and drop the I/O
 *		reference previously taken by calling fp_lookup et. al.
 *
 * Parameters:	p				Process in which the fd lives
 *		fd				fd associated with the fileproc
 *		fp				fileproc on which to set the
 *						flag and drop the reference
 *
 * Returns:	0				Success
 *	fp_drop:EBADF				Bad file descriptor
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the supplied process
 *
 * Notes:	The fileproc must correspond to the fd in the supplied proc
 */
int
fp_drop_event(proc_t p, int fd, struct fileproc *fp)
{
        int error;

	proc_fdlock_spin(p);

	fp->f_flags |= FP_WAITEVENT;
	
	error = fp_drop(p, fd, fp, 1);

	proc_fdunlock(p);
		
	return (error);
}


/*
 * fp_drop
 *
 * Description:	Drop the I/O reference previously taken by calling fp_lookup
 *		et. al.
 *
 * Parameters:	p				Process in which the fd lives
 *		fd				fd associated with the fileproc
 *		fp				fileproc on which to set the
 *						flag and drop the reference
 *		locked				flag to internally take and
 *						drop proc_fdlock if it is not
 *						already held by the caller
 *
 * Returns:	0				Success
 *		EBADF				Bad file descriptor
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the supplied process if 'locked' is non-zero, and assumes that
 *		the caller already holds this lock if 'locked' is non-zero.
 *
 * Notes:	The fileproc must correspond to the fd in the supplied proc
 */
int
fp_drop(proc_t p, int fd, struct fileproc *fp, int locked)
{
	struct filedesc *fdp = p->p_fd;
	int	needwakeup = 0;

	if (!locked)
		proc_fdlock_spin(p);
	 if ((fp == FILEPROC_NULL) && (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			((fdp->fd_ofileflags[fd] & UF_RESERVED) &&
			 !(fdp->fd_ofileflags[fd] & UF_CLOSING)))) {
		if (!locked)
			proc_fdunlock(p);
		return (EBADF);
	}
	fp->f_iocount--;

	if (fp->f_iocount == 0) {
		if (fp->f_flags & FP_SELCONFLICT)
			fp->f_flags &= ~FP_SELCONFLICT;

		if (p->p_fpdrainwait) {
			p->p_fpdrainwait = 0;
			needwakeup = 1;
		}
	}
	if (!locked)
		proc_fdunlock(p);
	if (needwakeup)
	        wakeup(&p->p_fpdrainwait);
		
	return (0);
}


/*
 * file_vnode
 *
 * Description:	Given an fd, look it up in the current process's per process
 *		open file table, and return its internal vnode pointer.
 *
 * Parameters:	fd				fd to obtain vnode from
 *		vpp				pointer to vnode return area
 *
 * Returns:	0				Success
 *		EINVAL				The fd does not refer to a
 *						vnode fileproc entry
 *	fp_lookup:EBADF				Bad file descriptor
 *
 * Implicit returns:
 *		*vpp (modified)			Returned vnode pointer
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the current process
 *
 * Notes:	If successful, this function increments the f_iocount on the
 *		fd's corresponding fileproc.
 *
 *		The fileproc referenced is not returned; because of this, care
 *		must be taken to not drop the last reference (e.g. by closing
 *		the file).  This is inherently unsafe, since the reference may
 *		not be recoverable from the vnode, if there is a subsequent
 *		close that destroys the associate fileproc.  The caller should
 *		therefore retain their own reference on the fileproc so that
 *		the f_iocount can be dropped subsequently.  Failure to do this
 *		can result in the returned pointer immediately becoming invalid
 *		following the call.
 *
 *		Use of this function is discouraged.
 */
int
file_vnode(int fd, struct vnode **vpp)
{
	proc_t p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock_spin(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (fp->f_type != DTYPE_VNODE) {
		fp_drop(p, fd, fp,1);
		proc_fdunlock(p);
		return(EINVAL);
	}
	if (vpp != NULL)
		*vpp = (struct vnode *)fp->f_data;
	proc_fdunlock(p);

	return(0);
}


/*
 * file_vnode_withvid
 *
 * Description:	Given an fd, look it up in the current process's per process
 *		open file table, and return its internal vnode pointer.
 *
 * Parameters:	fd				fd to obtain vnode from
 *		vpp				pointer to vnode return area
 *		vidp				pointer to vid of the returned vnode
 *
 * Returns:	0				Success
 *		EINVAL				The fd does not refer to a
 *						vnode fileproc entry
 *	fp_lookup:EBADF				Bad file descriptor
 *
 * Implicit returns:
 *		*vpp (modified)			Returned vnode pointer
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the current process
 *
 * Notes:	If successful, this function increments the f_iocount on the
 *		fd's corresponding fileproc.
 *
 *		The fileproc referenced is not returned; because of this, care
 *		must be taken to not drop the last reference (e.g. by closing
 *		the file).  This is inherently unsafe, since the reference may
 *		not be recoverable from the vnode, if there is a subsequent
 *		close that destroys the associate fileproc.  The caller should
 *		therefore retain their own reference on the fileproc so that
 *		the f_iocount can be dropped subsequently.  Failure to do this
 *		can result in the returned pointer immediately becoming invalid
 *		following the call.
 *
 *		Use of this function is discouraged.
 */
int
file_vnode_withvid(int fd, struct vnode **vpp, uint32_t * vidp)
{
	proc_t p = current_proc();
	struct fileproc *fp;
	vnode_t vp;
	int error;
	
	proc_fdlock_spin(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (fp->f_type != DTYPE_VNODE) {
		fp_drop(p, fd, fp,1);
		proc_fdunlock(p);
		return(EINVAL);
	}
	vp = (struct vnode *)fp->f_data;
	if (vpp != NULL) 
		*vpp = vp;

	if ((vidp != NULL) && (vp != NULLVP)) 
		*vidp = (uint32_t)vp->v_id;

	proc_fdunlock(p);

	return(0);
}


/*
 * file_socket
 *
 * Description:	Given an fd, look it up in the current process's per process
 *		open file table, and return its internal socket pointer.
 *
 * Parameters:	fd				fd to obtain vnode from
 *		sp				pointer to socket return area
 *
 * Returns:	0				Success
 *		ENOTSOCK			Not a socket
 *		fp_lookup:EBADF			Bad file descriptor
 *
 * Implicit returns:
 *		*sp (modified)			Returned socket pointer
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the current process
 *
 * Notes:	If successful, this function increments the f_iocount on the
 *		fd's corresponding fileproc.
 *
 *		The fileproc referenced is not returned; because of this, care
 *		must be taken to not drop the last reference (e.g. by closing
 *		the file).  This is inherently unsafe, since the reference may
 *		not be recoverable from the socket, if there is a subsequent
 *		close that destroys the associate fileproc.  The caller should
 *		therefore retain their own reference on the fileproc so that
 *		the f_iocount can be dropped subsequently.  Failure to do this
 *		can result in the returned pointer immediately becoming invalid
 *		following the call.
 *
 *		Use of this function is discouraged.
 */
int
file_socket(int fd, struct socket **sp)
{
	proc_t p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock_spin(p);
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


/*
 * file_flags
 *
 * Description:	Given an fd, look it up in the current process's per process
 *		open file table, and return its fileproc's flags field.
 *
 * Parameters:	fd				fd whose flags are to be
 *						retrieved
 *		flags				pointer to flags data area
 *
 * Returns:	0				Success
 *		ENOTSOCK			Not a socket
 *		fp_lookup:EBADF			Bad file descriptor
 *
 * Implicit returns:
 *		*flags (modified)		Returned flags field
 *
 * Locks:	This function internally takes and drops the proc_fdlock for
 *		the current process
 *
 * Notes:	This function will internally increment and decrement the
 *		f_iocount of the fileproc as part of its operation.
 */
int
file_flags(int fd, int *flags)
{

	proc_t p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock_spin(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	*flags = (int)fp->f_flag;
	fp_drop(p, fd, fp,1);
	proc_fdunlock(p);

	return(0);
}


/*
 * file_drop
 *
 * Description:	Drop an iocount reference on an fd, and wake up any waiters
 *		for draining (i.e. blocked in fileproc_drain() called during
 *		the last attempt to close a file).
 *
 * Parameters:	fd				fd on which an ioreference is
 *						to be dropped
 *
 * Returns:	0				Success
 *		EBADF				Bad file descriptor
 *
 * Description:	Given an fd, look it up in the current process's per process
 *		open file table, and drop it's fileproc's f_iocount by one
 *
 * Notes:	This is intended as a corresponding operation to the functions
 *		file_vnode() and file_socket() operations.
 *
 *		Technically, the close reference is supposed to be protected
 *		by a fileproc_drain(), however, a drain will only block if
 *		the fd refers to a character device, and that device has had
 *		preparefileread() called on it.  If it refers to something
 *		other than a character device, then the drain will occur and
 *		block each close attempt, rather than merely the last close.
 *
 *		Since it's possible for an fd that refers to a character
 *		device to have an intermediate close followed by an open to
 *		cause a different file to correspond to that descriptor,
 *		unless there was a cautionary reference taken on the fileproc,
 *		this is an inherently unsafe function.  This happens in the
 *		case where multiple fd's in a process refer to the same
 *		character device (e.g. stdin/out/err pointing to a tty, etc.).
 *
 *		Use of this function is discouraged.
 */
int 
file_drop(int fd)
{
	struct fileproc *fp;
	proc_t p = current_proc();
	int	needwakeup = 0;

	proc_fdlock_spin(p);
	if (fd < 0 || fd >= p->p_fd->fd_nfiles ||
			(fp = p->p_fd->fd_ofiles[fd]) == NULL ||
			((p->p_fd->fd_ofileflags[fd] & UF_RESERVED) &&
			 !(p->p_fd->fd_ofileflags[fd] & UF_CLOSING))) {
		proc_fdunlock(p);
		return (EBADF);
	}
	fp->f_iocount --;

	if (fp->f_iocount == 0) {
		if (fp->f_flags & FP_SELCONFLICT)
			fp->f_flags &= ~FP_SELCONFLICT;

		if (p->p_fpdrainwait) {
			p->p_fpdrainwait = 0;
			needwakeup = 1;
		}
	}
	proc_fdunlock(p);

	if (needwakeup)
	        wakeup(&p->p_fpdrainwait);
	return(0);
}


static int falloc_withalloc_locked(proc_t, struct fileproc **, int *,
    vfs_context_t, struct fileproc * (*)(void *), void *, int);

/*
 * falloc
 *
 * Description:	Allocate an entry in the per process open file table and
 *		return the corresponding fileproc and fd.
 *
 * Parameters:	p				The process in whose open file
 *						table the fd is to be allocated
 *		resultfp			Pointer to fileproc pointer
 *						return area
 *		resultfd			Pointer to fd return area
 *		ctx				VFS context
 *
 * Returns:	0				Success
 *	falloc:ENFILE				Too many open files in system
 *	falloc:EMFILE				Too many open files in process
 *	falloc:ENOMEM				M_FILEPROC or M_FILEGLOB zone
 *						exhausted
 *
 * Implicit returns:
 *		*resultfd (modified)		Returned fileproc pointer
 *		*resultfd (modified)		Returned fd
 *
 * Locks:	This function takes and drops the proc_fdlock; if this lock
 *		is already held, use falloc_locked() instead.
 *
 * Notes:	This function takes separate process and context arguments
 *		solely to support kern_exec.c; otherwise, it would take
 *		neither, and expect falloc_locked() to use the
 *		vfs_context_current() routine internally.
 */
int
falloc(proc_t p, struct fileproc **resultfp, int *resultfd, vfs_context_t ctx)
{
	return (falloc_withalloc(p, resultfp, resultfd, ctx,
	    fileproc_alloc_init, NULL));
}

/*
 * Like falloc, but including the fileproc allocator and create-args
 */
int
falloc_withalloc(proc_t p, struct fileproc **resultfp, int *resultfd,
    vfs_context_t ctx, fp_allocfn_t fp_zalloc, void *arg)
{
	int error;

	proc_fdlock(p);
	error = falloc_withalloc_locked(p,
	    resultfp, resultfd, ctx, fp_zalloc, arg, 1);
	proc_fdunlock(p);

	return (error);
}

/*
 * "uninitialized" ops -- ensure fg->fg_ops->fo_type always exists
 */
static const struct fileops uninitops;

/*
 * falloc_locked
 *
 * Create a new open file structure and allocate
 * a file descriptor for the process that refers to it.
 *
 * Returns:	0			Success
 *
 * Description:	Allocate an entry in the per process open file table and
 *		return the corresponding fileproc and fd.
 *
 * Parameters:	p				The process in whose open file
 *						table the fd is to be allocated
 *		resultfp			Pointer to fileproc pointer
 *						return area
 *		resultfd			Pointer to fd return area
 *		ctx				VFS context
 *		locked				Flag to indicate whether the
 *						caller holds proc_fdlock
 *
 * Returns:	0				Success
 *		ENFILE				Too many open files in system
 *		fdalloc:EMFILE			Too many open files in process
 *		ENOMEM				M_FILEPROC or M_FILEGLOB zone
 *						exhausted
 *	fdalloc:ENOMEM
 *
 * Implicit returns:
 *		*resultfd (modified)		Returned fileproc pointer
 *		*resultfd (modified)		Returned fd
 *
 * Locks:	If the parameter 'locked' is zero, this function takes and
 *		drops the proc_fdlock; if non-zero, the caller must hold the
 *		lock.
 *
 * Notes:	If you intend to use a non-zero 'locked' parameter, use the
 *		utility function falloc() instead.
 *
 *		This function takes separate process and context arguments
 *		solely to support kern_exec.c; otherwise, it would take
 *		neither, and use the vfs_context_current() routine internally.
 */
int
falloc_locked(proc_t p, struct fileproc **resultfp, int *resultfd,
	      vfs_context_t ctx, int locked)
{
	return (falloc_withalloc_locked(p, resultfp, resultfd, ctx,
	    fileproc_alloc_init, NULL, locked));
}

static int
falloc_withalloc_locked(proc_t p, struct fileproc **resultfp, int *resultfd,
    vfs_context_t ctx, fp_allocfn_t fp_zalloc, void *crarg,
    int locked)
{
	struct fileproc *fp;
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
#if CONFIG_MACF
	error = mac_file_check_create(proc_ucred(p));
	if (error) {
		if (!locked)
			proc_fdunlock(p);
		return (error);
	}
#endif

	/*
	 * Allocate a new file descriptor.
	 * If the process has file descriptor zero open, add to the list
	 * of open files at that point, otherwise put it at the front of
	 * the list of open files.
	 */
	proc_fdunlock(p);

	fp = (*fp_zalloc)(crarg);
	if (fp == NULL) {
		if (locked)
			proc_fdlock(p);
		return (ENOMEM);
	}
	MALLOC_ZONE(fg, struct fileglob *, sizeof(struct fileglob), M_FILEGLOB, M_WAITOK);
	if (fg == NULL) {
		fileproc_free(fp);
		if (locked)
			proc_fdlock(p);
		return (ENOMEM);
	}
	bzero(fg, sizeof(struct fileglob));
	lck_mtx_init(&fg->fg_lock, file_lck_grp, file_lck_attr);

	fp->f_iocount = 1;
	fg->fg_count = 1;
	fg->fg_ops = &uninitops;
	fp->f_fglob = fg;
#if CONFIG_MACF
	mac_file_label_init(fg);
#endif

	kauth_cred_ref(ctx->vc_ucred);

	proc_fdlock(p);

	fp->f_cred = ctx->vc_ucred;

#if CONFIG_MACF
	mac_file_label_associate(fp->f_cred, fg);
#endif

	OSAddAtomic(1, &nfiles);

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
 * fg_free
 *
 * Description:	Free a file structure; drop the global open file count, and
 *		drop the credential reference, if the fileglob has one, and
 *		destroy the instance mutex before freeing
 *
 * Parameters:	fg				Pointer to fileglob to be
 *						freed
 *
 * Returns:	void
 */
void
fg_free(struct fileglob *fg)
{
	OSAddAtomic(-1, &nfiles);

	if (fg->fg_vn_data) {
		fg_vn_data_free(fg->fg_vn_data);
		fg->fg_vn_data = NULL;
	}

	if (IS_VALID_CRED(fg->fg_cred)) {
		kauth_cred_unref(&fg->fg_cred);
	}
	lck_mtx_destroy(&fg->fg_lock, file_lck_grp);

#if CONFIG_MACF
	mac_file_label_destroy(fg);
#endif
	FREE_ZONE(fg, sizeof *fg, M_FILEGLOB);
}


/*
 * fdexec
 *
 * Description:	Perform close-on-exec processing for all files in a process
 *		that are either marked as close-on-exec, or which were in the
 *		process of being opened at the time of the execve
 *
 *		Also handles the case (via posix_spawn()) where -all-
 *		files except those marked with "inherit" as treated as
 *		close-on-exec.
 *
 * Parameters:	p				Pointer to process calling
 *						execve
 *
 * Returns:	void
 *
 * Locks:	This function internally takes and drops proc_fdlock()
 *
 */
void
fdexec(proc_t p, short flags)
{
	struct filedesc *fdp = p->p_fd;
	int i;
	boolean_t cloexec_default = (flags & POSIX_SPAWN_CLOEXEC_DEFAULT) != 0;

	proc_fdlock(p);
	for (i = fdp->fd_lastfile; i >= 0; i--) {

		struct fileproc *fp = fdp->fd_ofiles[i];
		char *flagp = &fdp->fd_ofileflags[i];

		if (fp && cloexec_default) {
			/*
			 * Reverse the usual semantics of file descriptor
			 * inheritance - all of them should be closed
			 * except files marked explicitly as "inherit" and
			 * not marked close-on-exec.
			 */
			if ((*flagp & (UF_EXCLOSE|UF_INHERIT)) != UF_INHERIT)
				*flagp |= UF_EXCLOSE;
			*flagp &= ~UF_INHERIT;
		}

		if (
		    ((*flagp & (UF_RESERVED|UF_EXCLOSE)) == UF_EXCLOSE)
#if CONFIG_MACF
		    || (fp && mac_file_check_inherit(proc_ucred(p), fp->f_fglob))
#endif
		) {
                        if (i < fdp->fd_knlistsize)
                                knote_fdclose(p, i);
			procfdtbl_clearfd(p, i);
			if (i == fdp->fd_lastfile && i > 0)
				fdp->fd_lastfile--;
			if (i < fdp->fd_freefile)
				fdp->fd_freefile = i;

			/*
			 * Wait for any third party viewers (e.g., lsof)
			 * to release their references to this fileproc.
			 */
			while (fp->f_iocount > 0) {
				p->p_fpdrainwait = 1;
				msleep(&p->p_fpdrainwait, &p->p_fdmlock, PRIBIO,
				    "fpdrain", NULL);
			}

			closef_locked(fp, fp->f_fglob, p);

			fileproc_free(fp);
		}
	}
	proc_fdunlock(p);
}


/*
 * fdcopy
 *
 * Description:	Copy a filedesc structure.  This is normally used as part of
 *		forkproc() when forking a new process, to copy the per process
 *		open file table over to the new process.
 *
 * Parameters:	p				Process whose open file table
 *						is to be copied (parent)
 *		uth_cdir			Per thread current working
 *						cirectory, or NULL
 *
 * Returns:	NULL				Copy failed
 *		!NULL				Pointer to new struct filedesc
 *
 * Locks:	This function internally takes and drops proc_fdlock()
 *
 * Notes:	Files are copied directly, ignoring the new resource limits
 *		for the process that's being copied into.  Since the descriptor
 *		references are just additional references, this does not count
 *		against the number of open files on the system.
 *
 *		The struct filedesc includes the current working directory,
 *		and the current root directory, if the process is chroot'ed.
 *
 *		If the exec was called by a thread using a per thread current
 *		working directory, we inherit the working directory from the
 *		thread making the call, rather than from the process.
 *
 *		In the case of a failure to obtain a reference, for most cases,
 *		the file entry will be silently dropped.  There's an exception
 *		for the case of a chroot dir, since a failure to to obtain a
 *		reference there would constitute an "escape" from the chroot
 *		environment, which must not be allowed.  In that case, we will
 *		deny the execve() operation, rather than allowing the escape.
 */
struct filedesc *
fdcopy(proc_t p, vnode_t uth_cdir)
{
	struct filedesc *newfdp, *fdp = p->p_fd;
	int i;
	struct fileproc *ofp, *fp;
	vnode_t	v_dir;

	MALLOC_ZONE(newfdp, struct filedesc *,
			sizeof(*newfdp), M_FILEDESC, M_WAITOK);
	if (newfdp == NULL)
		return(NULL);

	proc_fdlock(p);

	/*
	 * the FD_CHROOT flag will be inherited via this copy
	 */
	(void) memcpy(newfdp, fdp, sizeof(*newfdp));

	/*
	 * If we are running with per-thread current working directories,
	 * inherit the new current working directory from the current thread
	 * instead, before we take our references.
	 */
	if (uth_cdir != NULLVP)
		newfdp->fd_cdir = uth_cdir;

	/*
	 * For both fd_cdir and fd_rdir make sure we get
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
		 * be that much closer to recycling it
		 */
	        vnode_rele(fdp->fd_cdir);
		fdp->fd_cdir = NULL;
	}

	if ( (v_dir = newfdp->fd_rdir) ) {
		if (vnode_getwithref(v_dir) == 0) {
			if ( (vnode_ref(v_dir)) )
			        newfdp->fd_rdir = NULL;
			vnode_put(v_dir);
		} else {
		        newfdp->fd_rdir = NULL;
		}
	}
	/* Coming from a chroot environment and unable to get a reference... */
	if (newfdp->fd_rdir == NULL && fdp->fd_rdir) {
	        /*
		 * We couldn't get a new reference on
		 * the chroot directory being
		 * inherited... this is fatal, since
		 * otherwise it would constitute an
		 * escape from a chroot environment by
		 * the new process.
		 */
		if (newfdp->fd_cdir)
		        vnode_rele(newfdp->fd_cdir);
		FREE_ZONE(newfdp, sizeof *newfdp, M_FILEDESC);
		return(NULL);
	}

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
		while (i > 1 + 2 * NDEXTENT && i > 1 + newfdp->fd_lastfile * 2)
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

		FREE_ZONE(newfdp, sizeof(*newfdp), M_FILEDESC);
		return(NULL);
	}
	(void) memset(newfdp->fd_ofiles, 0, i * OFILESIZE);
	proc_fdlock(p);

	newfdp->fd_ofileflags = (char *) &newfdp->fd_ofiles[i];
	newfdp->fd_nfiles = i;

	if (fdp->fd_nfiles > 0) {
		struct fileproc **fpp;
		char *flags;

		(void) memcpy(newfdp->fd_ofiles, fdp->fd_ofiles,
					(newfdp->fd_lastfile + 1) * sizeof(*fdp->fd_ofiles));
		(void) memcpy(newfdp->fd_ofileflags, fdp->fd_ofileflags,
					(newfdp->fd_lastfile + 1) * sizeof(*fdp->fd_ofileflags));

		/*
		 * kq descriptors cannot be copied.
		 */
		if (newfdp->fd_knlistsize != -1) {
			fpp = &newfdp->fd_ofiles[newfdp->fd_lastfile];
			flags = &newfdp->fd_ofileflags[newfdp->fd_lastfile];
			for (i = newfdp->fd_lastfile;
			    i >= 0; i--, fpp--, flags--) {
				if (*flags & UF_RESERVED)
					continue;	/* (removed below) */
				if (*fpp != NULL && (*fpp)->f_type == DTYPE_KQUEUE) {
					*fpp = NULL;
					*flags = 0;
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

		for (i = newfdp->fd_lastfile + 1; --i >= 0; fpp++, flags++)
			if ((ofp = *fpp) != NULL &&
			    0 == (ofp->f_fglob->fg_lflags & FG_CONFINED) &&
			    0 == (*flags & (UF_FORKCLOSE|UF_RESERVED))) {
#if DEBUG
				if (FILEPROC_TYPE(ofp) != FTYPE_SIMPLE)
					panic("complex fileproc");
#endif
				fp = fileproc_alloc_init(NULL);
				if (fp == NULL) {
					/*
					 * XXX no room to copy, unable to
					 * XXX safely unwind state at present
					 */
					*fpp = NULL;
				} else {
					fp->f_flags |=
					    (ofp->f_flags & ~FP_TYPEMASK);
					fp->f_fglob = ofp->f_fglob;
					(void)fg_ref(fp);
					*fpp = fp;
				}
			} else {
				if (i < newfdp->fd_freefile)
					newfdp->fd_freefile = i;
				*fpp = NULL;
				*flags = 0;
			}
	}

	proc_fdunlock(p);
	return (newfdp);
}


/*
 * fdfree
 *
 * Description:	Release a filedesc (per process open file table) structure;
 *		this is done on process exit(), or from forkproc_free() if
 *		the fork fails for some reason subsequent to a successful
 *		call to fdcopy()
 *
 * Parameters:	p				Pointer to process going away
 *
 * Returns:	void
 *
 * Locks:	This function internally takes and drops proc_fdlock()
 */
void
fdfree(proc_t p)
{
	struct filedesc *fdp;
	struct fileproc *fp;
	int i;

	proc_fdlock(p);

	if (p == kernproc || NULL == (fdp = p->p_fd)) {
	        proc_fdunlock(p);
		return;
	}

	extern struct filedesc filedesc0;

	if (&filedesc0 == fdp)
		panic("filedesc0");

	if (fdp->fd_nfiles > 0 && fdp->fd_ofiles) {
	        for (i = fdp->fd_lastfile; i >= 0; i--) {
			if ((fp = fdp->fd_ofiles[i]) != NULL) {
			  
			  if (fdp->fd_ofileflags[i] & UF_RESERVED)
			    	panic("fdfree: found fp with UF_RESERVED");

				procfdtbl_reservefd(p, i);

				if (i < fdp->fd_knlistsize)
					knote_fdclose(p, i);
				if (fp->f_flags & FP_WAITEVENT) 
					(void)waitevent_close(p, fp);
				(void) closef_locked(fp, fp->f_fglob, p);
				fileproc_free(fp);
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

	proc_fdlock_spin(p);
	p->p_fd = NULL;
	proc_fdunlock(p);

	if (fdp->fd_knlist)
		FREE(fdp->fd_knlist, M_KQUEUE);
	if (fdp->fd_knhash)
		FREE(fdp->fd_knhash, M_KQUEUE);

	FREE_ZONE(fdp, sizeof(*fdp), M_FILEDESC);
}

/*
 * closef_locked
 *
 * Description:	Internal form of closef; called with proc_fdlock held
 *
 * Parameters:	fp			Pointer to fileproc for fd
 *		fg			Pointer to fileglob for fd
 *		p			Pointer to proc structure
 *
 * Returns:	0			Success
 *	closef_finish:??? 		Anything returnable by a per-fileops
 *					close function
 *
 * Note:	Decrements reference count on file structure; if this was the
 *		last reference, then closef_finish() is called
 *
 *		p and fp are allowed to  be NULL when closing a file that was
 *		being passed in a message (but only if we are called when this
 *		is NOT the last reference).
 */
int
closef_locked(struct fileproc *fp, struct fileglob *fg, proc_t p)
{
	struct vnode *vp;
	struct flock lf;
	struct vfs_context context;
	int error;

	if (fg == NULL) {
		return (0);
	}

	/* Set up context with cred stashed in fg */
	if (p == current_proc())
		context.vc_thread = current_thread();
	else
		context.vc_thread = NULL;
	context.vc_ucred = fg->fg_cred;

	/*
	 * POSIX record locking dictates that any close releases ALL
	 * locks owned by this process.  This is handled by setting
	 * a flag in the unlock to free ONLY locks obeying POSIX
	 * semantics, and not to free BSD-style file locks.
	 * If the descriptor was in a message, POSIX-style locks
	 * aren't passed with the descriptor.
	 */
	if (p && (p->p_ladvflag & P_LADVLOCK) &&
	    DTYPE_VNODE == FILEGLOB_DTYPE(fg)) {
		proc_fdunlock(p);

		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fg->fg_data;

		if ( (error = vnode_getwithref(vp)) == 0 ) {
			(void) VNOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &lf, F_POSIX, &context, NULL);
			(void)vnode_put(vp);
		}
		proc_fdlock(p);
	}
	lck_mtx_lock_spin(&fg->fg_lock);
	fg->fg_count--;

	if (fg->fg_count > 0) {
		lck_mtx_unlock(&fg->fg_lock);
		return (0);
	}
#if DIAGNOSTIC
	if (fg->fg_count != 0)
		panic("fg %p: being freed with bad fg_count (%d)", fg, fg->fg_count);
#endif

	if (fp && (fp->f_flags & FP_WRITTEN))
	        fg->fg_flag |= FWASWRITTEN;

	fg->fg_lflags |= FG_TERM;
	lck_mtx_unlock(&fg->fg_lock);

	if (p)
		proc_fdunlock(p);

	/* Since we ensure that fg->fg_ops is always initialized, 
	 * it is safe to invoke fo_close on the fg */
	error = fo_close(fg, &context);

	fg_free(fg);
	
	if (p)
		proc_fdlock(p);

	return(error);
}


/*
 * fileproc_drain
 *
 * Description:	Drain out pending I/O operations
 *
 * Parameters:	p				Process closing this file
 *		fp				fileproc struct for the open
 *						instance on the file
 *
 * Returns:	void
 *
 * Locks:	Assumes the caller holds the proc_fdlock
 *
 * Notes:	For character devices, this occurs on the last close of the
 *		device; for all other file descriptors, this occurs on each
 *		close to prevent fd's from being closed out from under
 *		operations currently in progress and blocked
 *
 * See Also: 	file_vnode(), file_socket(), file_drop(), and the cautions
 *		regarding their use and interaction with this function.
 */
void
fileproc_drain(proc_t p, struct fileproc * fp)
{
	struct vfs_context context;

	context.vc_thread = proc_thread(p);	/* XXX */
	context.vc_ucred = fp->f_fglob->fg_cred;

	fp->f_iocount-- ; /* (the one the close holds) */

	while (fp->f_iocount) {

	        lck_mtx_convert_spin(&p->p_fdmlock);

		if (fp->f_fglob->fg_ops->fo_drain) {
			(*fp->f_fglob->fg_ops->fo_drain)(fp, &context);
		}
		if ((fp->f_flags & FP_INSELECT) == FP_INSELECT) {
			if (waitq_wakeup64_all((struct waitq *)fp->f_wset, NO_EVENT64,
					       THREAD_INTERRUPTED, WAITQ_ALL_PRIORITIES) == KERN_INVALID_ARGUMENT)
				panic("bad wait queue for waitq_wakeup64_all %p (fp:%p)", fp->f_wset, fp);
		}
		if ((fp->f_flags & FP_SELCONFLICT) == FP_SELCONFLICT) {
			if (waitq_wakeup64_all(&select_conflict_queue, NO_EVENT64,
					       THREAD_INTERRUPTED, WAITQ_ALL_PRIORITIES) == KERN_INVALID_ARGUMENT)
				panic("bad select_conflict_queue");
		}
		p->p_fpdrainwait = 1;

		msleep(&p->p_fpdrainwait, &p->p_fdmlock, PRIBIO, "fpdrain", NULL);

	}
#if DIAGNOSTIC
	if ((fp->f_flags & FP_INSELECT) != 0)
		panic("FP_INSELECT set on drained fp");
#endif
	if ((fp->f_flags & FP_SELCONFLICT) == FP_SELCONFLICT)
		fp->f_flags &= ~FP_SELCONFLICT;
}


/*
 * fp_free
 *
 * Description:	Release the fd and free the fileproc associated with the fd
 *		in the per process open file table of the specified process;
 *		these values must correspond.
 *
 * Parameters:	p				Process containing fd
 *		fd				fd to be released
 *		fp				fileproc to be freed
 *
 * Returns:	0				Success
 *
 * Notes:	XXX function should be void - no one interprets the returns
 *		XXX code
 */
int
fp_free(proc_t p, int fd, struct fileproc * fp)
{
        proc_fdlock_spin(p);
	fdrelse(p, fd);
        proc_fdunlock(p);

	fg_free(fp->f_fglob);
	fileproc_free(fp);
	return(0);
}


/*
 * flock
 *
 * Description:	Apply an advisory lock on a file descriptor.
 *
 * Parameters:	p				Process making request
 *		uap->fd				fd on which the lock is to be
 *						attempted
 *		uap->how			(Un)Lock bits, including type
 *		retval				Pointer to the call return area
 *		
 * Returns:	0				Success
 *	fp_getfvp:EBADF				Bad file descriptor
 *	fp_getfvp:ENOTSUP			fd does not refer to a vnode
 *	vnode_getwithref:???
 *	VNOP_ADVLOCK:???
 *
 * Implicit returns:
 *		*retval (modified)		Size of dtable
 *
 * Notes:	Just attempt to get a record lock of the requested type on
 *		the entire file (l_whence = SEEK_SET, l_start = 0, l_len = 0).
 */
int
flock(proc_t p, struct flock_args *uap, __unused int32_t *retval)
{
	int fd = uap->fd;
	int how = uap->how;
	struct fileproc *fp;
	struct vnode *vp;
	struct flock lf;
	vfs_context_t ctx = vfs_context_current();
	int error=0;

	AUDIT_ARG(fd, uap->fd);
	if ( (error = fp_getfvp(p, fd, &fp, &vp)) ) {
		return(error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		goto out1;
	}
	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	if (how & LOCK_UN) {
		lf.l_type = F_UNLCK;
		fp->f_flag &= ~FHASLOCK;
		error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_UNLCK, &lf, F_FLOCK, ctx, NULL);
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
#if CONFIG_MACF
	error = mac_file_check_lock(proc_ucred(p), fp->f_fglob, F_SETLK, &lf);
	if (error)
		goto out;
#endif
	fp->f_flag |= FHASLOCK;
	if (how & LOCK_NB) {
		error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, F_FLOCK, ctx, NULL);
		goto out;	
	}
	error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, F_FLOCK|F_WAIT, ctx, NULL);
out:
	(void)vnode_put(vp);
out1:
	fp_drop(p, fd, fp, 0);
	return(error);

}

/*
 * fileport_makeport
 *
 * Description: Obtain a Mach send right for a given file descriptor.
 *
 * Parameters:	p		Process calling fileport
 * 		uap->fd		The fd to reference
 * 		uap->portnamep  User address at which to place port name.
 *
 * Returns:	0		Success.
 *     		EBADF		Bad file descriptor.
 *     		EINVAL		File descriptor had type that cannot be sent, misc. other errors.
 *     		EFAULT		Address at which to store port name is not valid.
 *     		EAGAIN		Resource shortage.
 *
 * Implicit returns:
 *		On success, name of send right is stored at user-specified address.		
 */
int
fileport_makeport(proc_t p, struct fileport_makeport_args *uap,
    __unused int *retval)
{
	int err;
	int fd = uap->fd;
	user_addr_t user_portaddr = uap->portnamep;
	struct fileproc *fp = FILEPROC_NULL;
	struct fileglob *fg = NULL;
	ipc_port_t fileport;
	mach_port_name_t name = MACH_PORT_NULL;

	proc_fdlock(p);
	err = fp_lookup(p, fd, &fp, 1);
	if (err != 0) {
		goto out_unlock;
	}

	if (!file_issendable(p, fp)) {
		err = EINVAL;
		goto out_unlock;
	}

	if (FP_ISGUARDED(fp, GUARD_FILEPORT)) {
		err = fp_guard_exception(p, fd, fp, kGUARD_EXC_FILEPORT);
		goto out_unlock;
	}

	/* Dropped when port is deallocated */
	fg = fp->f_fglob;
	fg_ref(fp);

	proc_fdunlock(p);

	/* Allocate and initialize a port */
	fileport = fileport_alloc(fg);
	if (fileport == IPC_PORT_NULL) {
		err = EAGAIN;
		fg_drop(fp);
		goto out;
	}
	
	/* Add an entry.  Deallocates port on failure. */
	name = ipc_port_copyout_send(fileport, get_task_ipcspace(p->task));
	if (!MACH_PORT_VALID(name)) {
		err = EINVAL;
		goto out;
	} 
	
	err = copyout(&name, user_portaddr, sizeof(mach_port_name_t));
	if (err != 0) {
		goto out;
	}

	/* Tag the fileglob for debugging purposes */
	lck_mtx_lock_spin(&fg->fg_lock);
	fg->fg_lflags |= FG_PORTMADE;
	lck_mtx_unlock(&fg->fg_lock);

	fp_drop(p, fd, fp, 0);

	return 0;

out_unlock:
	proc_fdunlock(p);
out:
	if (MACH_PORT_VALID(name)) {
		/* Don't care if another thread races us to deallocate the entry */
		(void) mach_port_deallocate(get_task_ipcspace(p->task), name);
	}

	if (fp != FILEPROC_NULL) {
		fp_drop(p, fd, fp, 0);
	}

	return err;
}

void
fileport_releasefg(struct fileglob *fg)
{
	(void)closef_locked(NULL, fg, PROC_NULL);

	return;
}


/*
 * fileport_makefd
 *
 * Description: Obtain the file descriptor for a given Mach send right.
 *
 * Parameters:	p		Process calling fileport
 * 		uap->port	Name of send right to file port.
 *
 * Returns:	0		Success
 *		EINVAL		Invalid Mach port name, or port is not for a file.
 *	fdalloc:EMFILE
 *	fdalloc:ENOMEM		Unable to allocate fileproc or extend file table.
 *
 * Implicit returns:
 *		*retval (modified)		The new descriptor
 */
int
fileport_makefd(proc_t p, struct fileport_makefd_args *uap, int32_t *retval)
{
	struct fileglob *fg;
 	struct fileproc *fp = FILEPROC_NULL;
	ipc_port_t port = IPC_PORT_NULL;
	mach_port_name_t send = uap->port;
	kern_return_t res;
	int fd;
	int err;

	res = ipc_object_copyin(get_task_ipcspace(p->task),
			send, MACH_MSG_TYPE_COPY_SEND, &port);

	if (res != KERN_SUCCESS) {
		err = EINVAL;
		goto out;
	}

	fg = fileport_port_to_fileglob(port);
	if (fg == NULL) {
		err = EINVAL;
		goto out;
	}

	fp = fileproc_alloc_init(NULL);
	if (fp == FILEPROC_NULL) {
		err = ENOMEM;
		goto out;
	}

	fp->f_fglob = fg;
	fg_ref(fp);

 	proc_fdlock(p);
	err = fdalloc(p, 0, &fd);
	if (err != 0) {
		proc_fdunlock(p);
		goto out;
	}
	*fdflags(p, fd) |= UF_EXCLOSE;

	procfdtbl_releasefd(p, fd, fp);
	proc_fdunlock(p);

	*retval = fd;
	err = 0;
out:
	if ((fp != NULL) && (0 != err)) {
		fileproc_free(fp);
	} 

	if (IPC_PORT_NULL != port) {
		ipc_port_release_send(port);
	}

	return err;
}


/*
 * dupfdopen
 *
 * Description:	Duplicate the specified descriptor to a free descriptor;
 *		this is the second half of fdopen(), above.
 *
 * Parameters:	fdp				filedesc pointer to fill in
 *		indx				fd to dup to
 *		dfd				fd to dup from
 *		mode				mode to set on new fd
 *		error				command code
 *
 * Returns:	0				Success
 *		EBADF				Source fd is bad
 *		EACCES				Requested mode not allowed
 *		!0				'error', if not ENODEV or
 *						ENXIO
 *
 * Notes:	XXX This is not thread safe; see fdopen() above
 */
int
dupfdopen(struct filedesc *fdp, int indx, int dfd, int flags, int error)
{
	struct fileproc *wfp;
	struct fileproc *fp;
#if CONFIG_MACF
	int myerror;
#endif
	proc_t p = current_proc();

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
#if CONFIG_MACF
	myerror = mac_file_check_dup(proc_ucred(p), wfp->f_fglob, dfd);
	if (myerror) {
		proc_fdunlock(p);
		return (myerror);
	}
#endif
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
		if (FP_ISGUARDED(wfp, GUARD_DUP)) {
			proc_fdunlock(p);
			return (EPERM);
		}

		/*
		 * Check that the mode the file is being opened for is a
		 * subset of the mode of the existing descriptor.
		 */
	        if (((flags & (FREAD|FWRITE)) | wfp->f_flag) != wfp->f_flag) {
		        proc_fdunlock(p);
			return (EACCES);
		}
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;
		(void)fg_ref(wfp);

		if (fp->f_fglob)
		        fg_free(fp->f_fglob);
		fp->f_fglob = wfp->f_fglob;

		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd] |
			(flags & O_CLOEXEC) ? UF_EXCLOSE : 0;

	        proc_fdunlock(p);
		return (0);

	default:
	        proc_fdunlock(p);
		return (error);
	}
	/* NOTREACHED */
}


/*
 * fg_ref
 *
 * Description:	Add a reference to a fileglob by fileproc
 *
 * Parameters:	fp				fileproc containing fileglob
 *						pointer
 *
 * Returns:	void
 *
 * Notes:	XXX Should use OSAddAtomic?
 */
void
fg_ref(struct fileproc * fp)
{
	struct fileglob *fg;

	fg = fp->f_fglob;

	lck_mtx_lock_spin(&fg->fg_lock);

#if DIAGNOSTIC
	if ((fp->f_flags & ~((unsigned int)FP_VALID_FLAGS)) != 0)
		panic("fg_ref: invalid bits on fp %p", fp);

	if (fg->fg_count == 0)
		panic("fg_ref: adding fgcount to zeroed fg: fp %p fg %p",
		    fp, fg);
#endif
	fg->fg_count++;
	lck_mtx_unlock(&fg->fg_lock);
}


/*
 * fg_drop
 *
 * Description:	Remove a reference to a fileglob by fileproc
 *
 * Parameters:	fp				fileproc containing fileglob
 *						pointer
 *
 * Returns:	void
 *
 * Notes:	XXX Should use OSAddAtomic?
 */
void
fg_drop(struct fileproc * fp)
{
	struct fileglob *fg;

	fg = fp->f_fglob;
	lck_mtx_lock_spin(&fg->fg_lock);
	fg->fg_count--;
	lck_mtx_unlock(&fg->fg_lock);
}

#if SOCKETS
/*
 * fg_insertuipc_mark
 *
 * Description:	Mark fileglob for insertion onto message queue if needed
 *		Also takes fileglob reference
 *
 * Parameters:	fg	Fileglob pointer to insert
 *
 * Returns:	true, if the fileglob needs to be inserted onto msg queue
 *
 * Locks:	Takes and drops fg_lock, potentially many times
 */
boolean_t
fg_insertuipc_mark(struct fileglob * fg)
{
	boolean_t insert = FALSE;

	lck_mtx_lock_spin(&fg->fg_lock);
	while (fg->fg_lflags & FG_RMMSGQ) {
		lck_mtx_convert_spin(&fg->fg_lock);

		fg->fg_lflags |= FG_WRMMSGQ;
		msleep(&fg->fg_lflags, &fg->fg_lock, 0, "fg_insertuipc", NULL);
	}

	fg->fg_count++;
	fg->fg_msgcount++;
	if (fg->fg_msgcount == 1) {
		fg->fg_lflags |= FG_INSMSGQ;
		insert = TRUE;
	}
	lck_mtx_unlock(&fg->fg_lock);
	return (insert);
}

/*
 * fg_insertuipc
 *
 * Description:	Insert marked fileglob onto message queue
 *
 * Parameters:	fg	Fileglob pointer to insert
 *
 * Returns:	void
 *
 * Locks:	Takes and drops fg_lock & uipc_lock
 *		DO NOT call this function with proc_fdlock held as unp_gc()
 *		can potentially try to acquire proc_fdlock, which can result
 *		in a deadlock if this function is in unp_gc_wait().
 */
void
fg_insertuipc(struct fileglob * fg)
{
	if (fg->fg_lflags & FG_INSMSGQ) {
		lck_mtx_lock_spin(uipc_lock);
		unp_gc_wait();
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

/*
 * fg_removeuipc_mark
 *
 * Description:	Mark the fileglob for removal from message queue if needed
 *		Also releases fileglob message queue reference
 *
 * Parameters:	fg	Fileglob pointer to remove
 *
 * Returns:	true, if the fileglob needs to be removed from msg queue
 *
 * Locks:	Takes and drops fg_lock, potentially many times
 */
boolean_t
fg_removeuipc_mark(struct fileglob * fg)
{
	boolean_t remove = FALSE;

	lck_mtx_lock_spin(&fg->fg_lock);
	while (fg->fg_lflags & FG_INSMSGQ) {
		lck_mtx_convert_spin(&fg->fg_lock);

		fg->fg_lflags |= FG_WINSMSGQ;
		msleep(&fg->fg_lflags, &fg->fg_lock, 0, "fg_removeuipc", NULL);
	}
	fg->fg_msgcount--;
	if (fg->fg_msgcount == 0) {
		fg->fg_lflags |= FG_RMMSGQ;
		remove = TRUE;
	}
	lck_mtx_unlock(&fg->fg_lock);
	return (remove);
}

/*
 * fg_removeuipc
 *
 * Description:	Remove marked fileglob from message queue
 *
 * Parameters:	fg	Fileglob pointer to remove
 *
 * Returns:	void
 *
 * Locks:	Takes and drops fg_lock & uipc_lock
 *		DO NOT call this function with proc_fdlock held as unp_gc()
 *		can potentially try to acquire proc_fdlock, which can result
 *		in a deadlock if this function is in unp_gc_wait().
 */
void
fg_removeuipc(struct fileglob * fg)
{
	if (fg->fg_lflags & FG_RMMSGQ) {
		lck_mtx_lock_spin(uipc_lock);
		unp_gc_wait();
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
#endif /* SOCKETS */

/*
 * fo_read
 *
 * Description:	Generic fileops read indirected through the fileops pointer
 *		in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer
 *		uio				user I/O structure pointer
 *		flags				FOF_ flags
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from read
 */
int
fo_read(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
	return ((*fp->f_ops->fo_read)(fp, uio, flags, ctx));
}


/*
 * fo_write
 *
 * Description:	Generic fileops write indirected through the fileops pointer
 *		in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer
 *		uio				user I/O structure pointer
 *		flags				FOF_ flags
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from write
 */
int
fo_write(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
	return((*fp->f_ops->fo_write)(fp, uio, flags, ctx));
}


/*
 * fo_ioctl
 *
 * Description:	Generic fileops ioctl indirected through the fileops pointer
 *		in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer
 *		com				ioctl command
 *		data				pointer to internalized copy
 *						of user space ioctl command
 *						parameter data in kernel space
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from ioctl
 *
 * Locks:	The caller is assumed to have held the proc_fdlock; this
 *		function releases and reacquires this lock.  If the caller
 *		accesses data protected by this lock prior to calling this
 *		function, it will need to revalidate/reacquire any cached
 *		protected data obtained prior to the call.
 */
int 
fo_ioctl(struct fileproc *fp, u_long com, caddr_t data, vfs_context_t ctx)
{
	int error;

	proc_fdunlock(vfs_context_proc(ctx));
	error = (*fp->f_ops->fo_ioctl)(fp, com, data, ctx);
	proc_fdlock(vfs_context_proc(ctx));
	return(error);
}       


/*
 * fo_select
 *
 * Description:	Generic fileops select indirected through the fileops pointer
 *		in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer
 *		which				select which
 *		wql				pointer to wait queue list
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from select
 */
int
fo_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{       
	return((*fp->f_ops->fo_select)(fp, which, wql, ctx));
}


/*
 * fo_close
 *
 * Description:	Generic fileops close indirected through the fileops pointer
 *		in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer for
 *						file to close
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from close
 */
int
fo_close(struct fileglob *fg, vfs_context_t ctx)
{       
	return((*fg->fg_ops->fo_close)(fg, ctx));
}


/*
 * fo_kqfilter
 *
 * Description:	Generic fileops kqueue filter indirected through the fileops
 *		pointer in the fileproc structure
 *
 * Parameters:	fp				fileproc structure pointer
 *		kn				pointer to knote to filter on
 *		ctx				VFS context for operation
 *
 * Returns:	0				Success
 *		!0				Errno from kqueue filter
 */
int
fo_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx)
{
        return ((*fp->f_ops->fo_kqfilter)(fp, kn, ctx));
}

/*
 * The ability to send a file descriptor to another
 * process is opt-in by file type.
 */
boolean_t
file_issendable(proc_t p, struct fileproc *fp) 
{
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);

	switch (fp->f_type) {
	case DTYPE_VNODE:
	case DTYPE_SOCKET:
	case DTYPE_PIPE:
	case DTYPE_PSXSHM:
		return (0 == (fp->f_fglob->fg_lflags & FG_CONFINED));
	default:
		/* DTYPE_KQUEUE, DTYPE_FSEVENTS, DTYPE_PSXSEM */
		return FALSE;
	}
}


struct fileproc *
fileproc_alloc_init(__unused void *arg)
{
	struct fileproc *fp;

	MALLOC_ZONE(fp, struct fileproc *, sizeof (*fp), M_FILEPROC, M_WAITOK);
	if (fp)
		bzero(fp, sizeof (*fp));

	return (fp);
}

void
fileproc_free(struct fileproc *fp)
{
	switch (FILEPROC_TYPE(fp)) {
	case FTYPE_SIMPLE:
		FREE_ZONE(fp, sizeof (*fp), M_FILEPROC);
		break;
	case FTYPE_GUARDED:
		guarded_fileproc_free(fp);
		break;
	default:
		panic("%s: corrupt fp %p flags %x", __func__, fp, fp->f_flags);
	}
}
