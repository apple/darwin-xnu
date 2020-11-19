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
 *	@(#)sys_generic.c	8.9 (Berkeley) 2/14/95
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
#include <sys/ioctl.h>
#include <sys/file_internal.h>
#include <sys/proc_internal.h>
#include <sys/socketvar.h>
#include <sys/uio_internal.h>
#include <sys/kernel.h>
#include <sys/guarded.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>

#include <sys/mount_internal.h>
#include <sys/protosw.h>
#include <sys/ev.h>
#include <sys/user.h>
#include <sys/kdebug.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <machine/smp.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/ledger.h>
#include <kern/task.h>
#include <kern/telemetry.h>
#include <kern/waitq.h>
#include <kern/sched_prim.h>
#include <kern/mpsc_queue.h>
#include <kern/debug.h>

#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/pipe.h>

#include <security/audit/audit.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>
/* for wait queue based select */
#include <kern/waitq.h>
#include <sys/vnode_internal.h>
/* for remote time api*/
#include <kern/remote_time.h>
#include <os/log.h>
#include <sys/log_data.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/* for entitlement check */
#include <IOKit/IOBSD.h>

/* XXX should be in a header file somewhere */
extern kern_return_t IOBSDGetPlatformUUID(__darwin_uuid_t uuid, mach_timespec_t timeoutp);

int rd_uio(struct proc *p, int fdes, uio_t uio, int is_preadv, user_ssize_t *retval);
int wr_uio(struct proc *p, int fdes, uio_t uio, int is_pwritev, user_ssize_t *retval);
int do_uiowrite(struct proc *p, struct fileproc *fp, uio_t uio, int flags, user_ssize_t *retval);

__private_extern__ int  dofileread(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int  dofilewrite(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte,
    off_t offset, int flags, user_ssize_t *retval);
static int preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_vnode);

/* Conflict wait queue for when selects collide (opaque type) */
struct waitq select_conflict_queue;

/*
 * Init routine called from bsd_init.c
 */
void select_waitq_init(void);
void
select_waitq_init(void)
{
	waitq_init(&select_conflict_queue, SYNC_POLICY_FIFO);
}

#define f_flag fp_glob->fg_flag
#define f_type fp_glob->fg_ops->fo_type
#define f_cred fp_glob->fg_cred
#define f_ops fp_glob->fg_ops
#define f_data fp_glob->fg_data

/*
 * Read system call.
 *
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	preparefileread:EBADF
 *	dofileread:???
 */
int
read(struct proc *p, struct read_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return read_nocancel(p, (struct read_nocancel_args *)uap, retval);
}

int
read_nocancel(struct proc *p, struct read_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	int fd = uap->fd;
	struct vfs_context context;

	if ((error = preparefileread(p, &fp, fd, 0))) {
		return error;
	}

	context = *(vfs_context_current());
	context.vc_ucred = fp->fp_glob->fg_cred;

	error = dofileread(&context, fp, uap->cbuf, uap->nbyte,
	    (off_t)-1, 0, retval);

	fp_drop(p, fd, fp, 0);

	return error;
}

/*
 * Pread system call
 *
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	preparefileread:EBADF
 *	dofileread:???
 */
int
pread(struct proc *p, struct pread_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return pread_nocancel(p, (struct pread_nocancel_args *)uap, retval);
}

int
pread_nocancel(struct proc *p, struct pread_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp = NULL;     /* fp set by preparefileread() */
	int fd = uap->fd;
	int error;
	struct vfs_context context;

	if ((error = preparefileread(p, &fp, fd, 1))) {
		goto out;
	}

	context = *(vfs_context_current());
	context.vc_ucred = fp->fp_glob->fg_cred;

	error = dofileread(&context, fp, uap->buf, uap->nbyte,
	    uap->offset, FOF_OFFSET, retval);

	fp_drop(p, fd, fp, 0);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pread) | DBG_FUNC_NONE),
	    uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

out:
	return error;
}

/*
 * Code common for read and pread
 */

/*
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *	fp_lookup:EBADF
 */
static int
preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pread)
{
	vnode_t vp;
	int     error;
	struct fileproc *fp;

	AUDIT_ARG(fd, fd);

	proc_fdlock_spin(p);

	error = fp_lookup(p, fd, &fp, 1);

	if (error) {
		proc_fdunlock(p);
		return error;
	}
	if ((fp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (check_for_pread && (fp->f_type != DTYPE_VNODE)) {
		error = ESPIPE;
		goto out;
	}
	if (fp->f_type == DTYPE_VNODE) {
		vp = (struct vnode *)fp->fp_glob->fg_data;

		if (check_for_pread && (vnode_isfifo(vp))) {
			error = ESPIPE;
			goto out;
		}
		if (check_for_pread && (vp->v_flag & VISTTY)) {
			error = ENXIO;
			goto out;
		}
	}

	*fp_ret = fp;

	proc_fdunlock(p);
	return 0;

out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return error;
}


/*
 * Returns:	0			Success
 *		EINVAL
 *	fo_read:???
 */
__private_extern__ int
dofileread(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte, off_t offset, int flags,
    user_ssize_t *retval)
{
	uio_t auio;
	user_ssize_t bytecnt;
	int error = 0;
	char uio_buf[UIO_SIZEOF(1)];

	if (nbyte > INT_MAX) {
		return EINVAL;
	}

	if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_READ,
		    &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_READ,
		    &uio_buf[0], sizeof(uio_buf));
	}
	if (uio_addiov(auio, bufp, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	bytecnt = nbyte;

	if ((error = fo_read(fp, auio, flags, ctx))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK)) {
			error = 0;
		}
	}
	bytecnt -= uio_resid(auio);

	*retval = bytecnt;

	return error;
}

/*
 * Vector read.
 *
 * Returns:    0                       Success
 *             EINVAL
 *             ENOMEM
 *     preparefileread:EBADF
 *     preparefileread:ESPIPE
 *     preparefileread:ENXIO
 *     preparefileread:EBADF
 *     copyin:EFAULT
 *     rd_uio:???
 */
static int
readv_preadv_uio(struct proc *p, int fdes,
    user_addr_t user_iovp, int iovcnt, off_t offset, int is_preadv,
    user_ssize_t *retval)
{
	uio_t auio = NULL;
	int error;
	struct user_iovec *iovp;

	/* Verify range before calling uio_create() */
	if (iovcnt <= 0 || iovcnt > UIO_MAXIOV) {
		return EINVAL;
	}

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(iovcnt, offset,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	    UIO_READ);

	/* get location of iovecs within the uio.  then copyin the iovecs from
	 * user space.
	 */
	iovp = uio_iovsaddr(auio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto ExitThisRoutine;
	}
	error = copyin_user_iovec_array(user_iovp,
	    IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
	    iovcnt, iovp);
	if (error) {
		goto ExitThisRoutine;
	}

	/* finalize uio_t for use and do the IO
	 */
	error = uio_calculateresid(auio);
	if (error) {
		goto ExitThisRoutine;
	}
	error = rd_uio(p, fdes, auio, is_preadv, retval);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return error;
}

/*
 * Scatter read system call.
 */
int
readv(struct proc *p, struct readv_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return readv_nocancel(p, (struct readv_nocancel_args *)uap, retval);
}

int
readv_nocancel(struct proc *p, struct readv_nocancel_args *uap, user_ssize_t *retval)
{
	return readv_preadv_uio(p, uap->fd, uap->iovp, uap->iovcnt, 0, 0, retval);
}

/*
 * Preadv system call
 */
int
sys_preadv(struct proc *p, struct preadv_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return sys_preadv_nocancel(p, (struct preadv_nocancel_args *)uap, retval);
}

int
sys_preadv_nocancel(struct proc *p, struct preadv_nocancel_args *uap, user_ssize_t *retval)
{
	return readv_preadv_uio(p, uap->fd, uap->iovp, uap->iovcnt, uap->offset, 1, retval);
}

/*
 * Write system call
 *
 * Returns:	0			Success
 *		EBADF
 *	fp_lookup:EBADF
 *	dofilewrite:???
 */
int
write(struct proc *p, struct write_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return write_nocancel(p, (struct write_nocancel_args *)uap, retval);
}

int
write_nocancel(struct proc *p, struct write_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	int fd = uap->fd;

	AUDIT_ARG(fd, fd);

	error = fp_lookup(p, fd, &fp, 0);
	if (error) {
		return error;
	}
	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		proc_fdlock(p);
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
		proc_fdunlock(p);
	} else {
		struct vfs_context context = *(vfs_context_current());
		context.vc_ucred = fp->fp_glob->fg_cred;

		error = dofilewrite(&context, fp, uap->cbuf, uap->nbyte,
		    (off_t)-1, 0, retval);
	}
	fp_drop(p, fd, fp, 0);
	return error;
}

/*
 * pwrite system call
 *
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *		EINVAL
 *	fp_lookup:EBADF
 *	dofilewrite:???
 */
int
pwrite(struct proc *p, struct pwrite_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return pwrite_nocancel(p, (struct pwrite_nocancel_args *)uap, retval);
}

int
pwrite_nocancel(struct proc *p, struct pwrite_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	int fd = uap->fd;
	vnode_t vp  = (vnode_t)0;

	AUDIT_ARG(fd, fd);

	error = fp_get_ftype(p, fd, DTYPE_VNODE, ESPIPE, &fp);
	if (error) {
		return error;
	}

	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		proc_fdlock(p);
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
		proc_fdunlock(p);
	} else {
		struct vfs_context context = *vfs_context_current();
		context.vc_ucred = fp->fp_glob->fg_cred;

		vp = (vnode_t)fp->fp_glob->fg_data;
		if (vnode_isfifo(vp)) {
			error = ESPIPE;
			goto errout;
		}
		if ((vp->v_flag & VISTTY)) {
			error = ENXIO;
			goto errout;
		}
		if (uap->offset == (off_t)-1) {
			error = EINVAL;
			goto errout;
		}

		error = dofilewrite(&context, fp, uap->buf, uap->nbyte,
		    uap->offset, FOF_OFFSET, retval);
	}
errout:
	fp_drop(p, fd, fp, 0);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pwrite) | DBG_FUNC_NONE),
	    uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

	return error;
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	<fo_write>:EPIPE
 *	<fo_write>:???			[indirect through struct fileops]
 */
__private_extern__ int
dofilewrite(vfs_context_t ctx, struct fileproc *fp,
    user_addr_t bufp, user_size_t nbyte, off_t offset, int flags,
    user_ssize_t *retval)
{
	uio_t auio;
	int error = 0;
	user_ssize_t bytecnt;
	char uio_buf[UIO_SIZEOF(1)];

	if (nbyte > INT_MAX) {
		*retval = 0;
		return EINVAL;
	}

	if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_WRITE,
		    &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_WRITE,
		    &uio_buf[0], sizeof(uio_buf));
	}
	if (uio_addiov(auio, bufp, nbyte) != 0) {
		*retval = 0;
		return EINVAL;
	}

	bytecnt = nbyte;
	if ((error = fo_write(fp, auio, flags, ctx))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK)) {
			error = 0;
		}
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET &&
		    (fp->fp_glob->fg_lflags & FG_NOSIGPIPE) == 0) {
			/* XXX Raise the signal on the thread? */
			psignal(vfs_context_proc(ctx), SIGPIPE);
		}
	}
	bytecnt -= uio_resid(auio);
	if (bytecnt) {
		os_atomic_or(&fp->fp_glob->fg_flag, FWASWRITTEN, relaxed);
	}
	*retval = bytecnt;

	return error;
}

/*
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *	fp_lookup:EBADF
 *	fp_guard_exception:???
 */
static int
preparefilewrite(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pwrite)
{
	vnode_t vp;
	int error;
	struct fileproc *fp;

	AUDIT_ARG(fd, fd);

	proc_fdlock_spin(p);

	error = fp_lookup(p, fd, &fp, 1);

	if (error) {
		proc_fdunlock(p);
		return error;
	}
	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
		goto ExitThisRoutine;
	}
	if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
		goto ExitThisRoutine;
	}
	if (check_for_pwrite) {
		if (fp->f_type != DTYPE_VNODE) {
			error = ESPIPE;
			goto ExitThisRoutine;
		}

		vp = (vnode_t)fp->fp_glob->fg_data;
		if (vnode_isfifo(vp)) {
			error = ESPIPE;
			goto ExitThisRoutine;
		}
		if ((vp->v_flag & VISTTY)) {
			error = ENXIO;
			goto ExitThisRoutine;
		}
	}

	*fp_ret = fp;

	proc_fdunlock(p);
	return 0;

ExitThisRoutine:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return error;
}

static int
writev_prwritev_uio(struct proc *p, int fd,
    user_addr_t user_iovp, int iovcnt, off_t offset, int is_pwritev,
    user_ssize_t *retval)
{
	uio_t auio = NULL;
	int error;
	struct user_iovec *iovp;

	/* Verify range before calling uio_create() */
	if (iovcnt <= 0 || iovcnt > UIO_MAXIOV || offset < 0) {
		return EINVAL;
	}

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(iovcnt, offset,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	    UIO_WRITE);

	/* get location of iovecs within the uio.  then copyin the iovecs from
	 * user space.
	 */
	iovp = uio_iovsaddr(auio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto ExitThisRoutine;
	}
	error = copyin_user_iovec_array(user_iovp,
	    IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
	    iovcnt, iovp);
	if (error) {
		goto ExitThisRoutine;
	}

	/* finalize uio_t for use and do the IO
	 */
	error = uio_calculateresid(auio);
	if (error) {
		goto ExitThisRoutine;
	}

	error = wr_uio(p, fd, auio, is_pwritev, retval);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return error;
}

/*
 * Gather write system call
 */
int
writev(struct proc *p, struct writev_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return writev_nocancel(p, (struct writev_nocancel_args *)uap, retval);
}

int
writev_nocancel(struct proc *p, struct writev_nocancel_args *uap, user_ssize_t *retval)
{
	return writev_prwritev_uio(p, uap->fd, uap->iovp, uap->iovcnt, 0, 0, retval);
}

/*
 * Pwritev system call
 */
int
sys_pwritev(struct proc *p, struct pwritev_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return sys_pwritev_nocancel(p, (struct pwritev_nocancel_args *)uap, retval);
}

int
sys_pwritev_nocancel(struct proc *p, struct pwritev_nocancel_args *uap, user_ssize_t *retval)
{
	return writev_prwritev_uio(p, uap->fd, uap->iovp, uap->iovcnt, uap->offset, 1, retval);
}

/*
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	preparefileread:???
 *	fo_write:???
 */
int
wr_uio(struct proc *p, int fd, uio_t uio, int is_pwritev, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	int flags;

	if ((error = preparefilewrite(p, &fp, fd, is_pwritev))) {
		return error;
	}

	flags = is_pwritev ? FOF_OFFSET : 0;
	error = do_uiowrite(p, fp, uio, flags, retval);

	fp_drop(p, fd, fp, 0);

	return error;
}

int
do_uiowrite(struct proc *p, struct fileproc *fp, uio_t uio, int flags, user_ssize_t *retval)
{
	int error;
	user_ssize_t count;
	struct vfs_context context = *vfs_context_current();

	count = uio_resid(uio);

	context.vc_ucred = fp->f_cred;
	error = fo_write(fp, uio, flags, &context);
	if (error) {
		if (uio_resid(uio) != count && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK)) {
			error = 0;
		}
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET &&
		    (fp->fp_glob->fg_lflags & FG_NOSIGPIPE) == 0) {
			psignal(p, SIGPIPE);
		}
	}
	count -= uio_resid(uio);
	if (count) {
		os_atomic_or(&fp->fp_glob->fg_flag, FWASWRITTEN, relaxed);
	}
	*retval = count;

	return error;
}

/*
 * Returns:	0			Success
 *	preparefileread:EBADF
 *	preparefileread:ESPIPE
 *	preparefileread:ENXIO
 *	fo_read:???
 */
int
rd_uio(struct proc *p, int fdes, uio_t uio, int is_preadv, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	user_ssize_t count;
	struct vfs_context context = *vfs_context_current();

	if ((error = preparefileread(p, &fp, fdes, is_preadv))) {
		return error;
	}

	count = uio_resid(uio);

	context.vc_ucred = fp->f_cred;

	int flags = is_preadv ? FOF_OFFSET : 0;
	error = fo_read(fp, uio, flags, &context);

	if (error) {
		if (uio_resid(uio) != count && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK)) {
			error = 0;
		}
	}
	*retval = count - uio_resid(uio);

	fp_drop(p, fdes, fp, 0);

	return error;
}

/*
 * Ioctl system call
 *
 * Returns:	0			Success
 *		EBADF
 *		ENOTTY
 *		ENOMEM
 *		ESRCH
 *	copyin:EFAULT
 *	copyoutEFAULT
 *	fp_lookup:EBADF			Bad file descriptor
 *	fo_ioctl:???
 */
int
ioctl(struct proc *p, struct ioctl_args *uap, __unused int32_t *retval)
{
	struct fileproc *fp = NULL;
	int error = 0;
	u_int size = 0;
	caddr_t datap = NULL, memp = NULL;
	boolean_t is64bit = FALSE;
	int tmp = 0;
#define STK_PARAMS      128
	char stkbuf[STK_PARAMS] = {};
	int fd = uap->fd;
	u_long com = uap->com;
	struct vfs_context context = *vfs_context_current();

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(addr, uap->data);

	is64bit = proc_is64bit(p);
#if CONFIG_AUDIT
	if (is64bit) {
		AUDIT_ARG(value64, com);
	} else {
		AUDIT_ARG(cmd, CAST_DOWN_EXPLICIT(int, com));
	}
#endif /* CONFIG_AUDIT */

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if (size > IOCPARM_MAX) {
		return ENOTTY;
	}
	if (size > sizeof(stkbuf)) {
		memp = (caddr_t)kheap_alloc(KHEAP_TEMP, size, Z_WAITOK);
		if (memp == 0) {
			return ENOMEM;
		}
		datap = memp;
	} else {
		datap = &stkbuf[0];
	}
	if (com & IOC_IN) {
		if (size) {
			error = copyin(uap->data, datap, size);
			if (error) {
				goto out_nofp;
			}
		} else {
			/* XXX - IOC_IN and no size?  we should proably return an error here!! */
			if (is64bit) {
				*(user_addr_t *)datap = uap->data;
			} else {
				*(uint32_t *)datap = (uint32_t)uap->data;
			}
		}
	} else if ((com & IOC_OUT) && size) {
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(datap, size);
	} else if (com & IOC_VOID) {
		/* XXX - this is odd since IOC_VOID means no parameters */
		if (is64bit) {
			*(user_addr_t *)datap = uap->data;
		} else {
			*(uint32_t *)datap = (uint32_t)uap->data;
		}
	}

	proc_fdlock(p);
	error = fp_lookup(p, fd, &fp, 1);
	if (error) {
		proc_fdunlock(p);
		goto out_nofp;
	}

	AUDIT_ARG(file, p, fp);

	if ((fp->f_flag & (FREAD | FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}

	context.vc_ucred = fp->fp_glob->fg_cred;

#if CONFIG_MACF
	error = mac_file_check_ioctl(context.vc_ucred, fp->fp_glob, com);
	if (error) {
		goto out;
	}
#endif

	switch (com) {
	case FIONCLEX:
		*fdflags(p, fd) &= ~UF_EXCLOSE;
		break;

	case FIOCLEX:
		*fdflags(p, fd) |= UF_EXCLOSE;
		break;

	case FIONBIO:
		// FIXME (rdar://54898652)
		//
		// this code is broken if fnctl(F_SETFL), ioctl() are
		// called concurrently for the same fileglob.
		if ((tmp = *(int *)datap)) {
			os_atomic_or(&fp->f_flag, FNONBLOCK, relaxed);
		} else {
			os_atomic_andnot(&fp->f_flag, FNONBLOCK, relaxed);
		}
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, &context);
		break;

	case FIOASYNC:
		// FIXME (rdar://54898652)
		//
		// this code is broken if fnctl(F_SETFL), ioctl() are
		// called concurrently for the same fileglob.
		if ((tmp = *(int *)datap)) {
			os_atomic_or(&fp->f_flag, FASYNC, relaxed);
		} else {
			os_atomic_andnot(&fp->f_flag, FASYNC, relaxed);
		}
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, &context);
		break;

	case FIOSETOWN:
		tmp = *(int *)datap;
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			break;
		}
		if (fp->f_type == DTYPE_PIPE) {
			error = fo_ioctl(fp, TIOCSPGRP, (caddr_t)&tmp, &context);
			break;
		}
		if (tmp <= 0) {
			tmp = -tmp;
		} else {
			struct proc *p1 = proc_find(tmp);
			if (p1 == 0) {
				error = ESRCH;
				break;
			}
			tmp = p1->p_pgrpid;
			proc_rele(p1);
		}
		error = fo_ioctl(fp, TIOCSPGRP, (caddr_t)&tmp, &context);
		break;

	case FIOGETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			*(int *)datap = ((struct socket *)fp->f_data)->so_pgid;
			break;
		}
		error = fo_ioctl(fp, TIOCGPGRP, datap, &context);
		*(int *)datap = -*(int *)datap;
		break;

	default:
		error = fo_ioctl(fp, com, datap, &context);
		/*
		 * Copy any data to user, size was
		 * already set and checked above.
		 */
		if (error == 0 && (com & IOC_OUT) && size) {
			error = copyout(datap, uap->data, (u_int)size);
		}
		break;
	}
out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

out_nofp:
	if (memp) {
		kheap_free(KHEAP_TEMP, memp, size);
	}
	return error;
}

int     selwait, nselcoll;
#define SEL_FIRSTPASS 1
#define SEL_SECONDPASS 2
extern int selcontinue(int error);
extern int selprocess(int error, int sel_pass);
static int selscan(struct proc *p, struct _select * sel, struct _select_data * seldata,
    int nfd, int32_t *retval, int sel_pass, struct waitq_set *wqset);
static int selcount(struct proc *p, u_int32_t *ibits, int nfd, int *count);
static int seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup);
static int seldrop(struct proc *p, u_int32_t *ibits, int nfd, int lim);
static int select_internal(struct proc *p, struct select_nocancel_args *uap, uint64_t timeout, int32_t *retval);

/*
 * Select system call.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EAGAIN			Nonconformant error if allocation fails
 */
int
select(struct proc *p, struct select_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return select_nocancel(p, (struct select_nocancel_args *)uap, retval);
}

int
select_nocancel(struct proc *p, struct select_nocancel_args *uap, int32_t *retval)
{
	uint64_t timeout = 0;

	if (uap->tv) {
		int err;
		struct timeval atv;
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval atv64;
			err = copyin(uap->tv, (caddr_t)&atv64, sizeof(atv64));
			/* Loses resolution - assume timeout < 68 years */
			atv.tv_sec = (__darwin_time_t)atv64.tv_sec;
			atv.tv_usec = atv64.tv_usec;
		} else {
			struct user32_timeval atv32;
			err = copyin(uap->tv, (caddr_t)&atv32, sizeof(atv32));
			atv.tv_sec = atv32.tv_sec;
			atv.tv_usec = atv32.tv_usec;
		}
		if (err) {
			return err;
		}

		if (itimerfix(&atv)) {
			err = EINVAL;
			return err;
		}

		clock_absolutetime_interval_to_deadline(tvtoabstime(&atv), &timeout);
	}

	return select_internal(p, uap, timeout, retval);
}

int
pselect(struct proc *p, struct pselect_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return pselect_nocancel(p, (struct pselect_nocancel_args *)uap, retval);
}

int
pselect_nocancel(struct proc *p, struct pselect_nocancel_args *uap, int32_t *retval)
{
	int err;
	struct uthread *ut;
	uint64_t timeout = 0;

	if (uap->ts) {
		struct timespec ts;

		if (IS_64BIT_PROCESS(p)) {
			struct user64_timespec ts64;
			err = copyin(uap->ts, (caddr_t)&ts64, sizeof(ts64));
			ts.tv_sec = (__darwin_time_t)ts64.tv_sec;
			ts.tv_nsec = (long)ts64.tv_nsec;
		} else {
			struct user32_timespec ts32;
			err = copyin(uap->ts, (caddr_t)&ts32, sizeof(ts32));
			ts.tv_sec = ts32.tv_sec;
			ts.tv_nsec = ts32.tv_nsec;
		}
		if (err) {
			return err;
		}

		if (!timespec_is_valid(&ts)) {
			return EINVAL;
		}
		clock_absolutetime_interval_to_deadline(tstoabstime(&ts), &timeout);
	}

	ut = get_bsdthread_info(current_thread());

	if (uap->mask != USER_ADDR_NULL) {
		/* save current mask, then copyin and set new mask */
		sigset_t newset;
		err = copyin(uap->mask, &newset, sizeof(sigset_t));
		if (err) {
			return err;
		}
		ut->uu_oldmask = ut->uu_sigmask;
		ut->uu_flag |= UT_SAS_OLDMASK;
		ut->uu_sigmask = (newset & ~sigcantmask);
	}

	err = select_internal(p, (struct select_nocancel_args *)uap, timeout, retval);

	if (err != EINTR && ut->uu_flag & UT_SAS_OLDMASK) {
		/*
		 * Restore old mask (direct return case). NOTE: EINTR can also be returned
		 * if the thread is cancelled. In that case, we don't reset the signal
		 * mask to its original value (which usually happens in the signal
		 * delivery path). This behavior is permitted by POSIX.
		 */
		ut->uu_sigmask = ut->uu_oldmask;
		ut->uu_oldmask = 0;
		ut->uu_flag &= ~UT_SAS_OLDMASK;
	}

	return err;
}

/*
 * Generic implementation of {,p}select. Care: we type-pun uap across the two
 * syscalls, which differ slightly. The first 4 arguments (nfds and the fd sets)
 * are identical. The 5th (timeout) argument points to different types, so we
 * unpack in the syscall-specific code, but the generic code still does a null
 * check on this argument to determine if a timeout was specified.
 */
static int
select_internal(struct proc *p, struct select_nocancel_args *uap, uint64_t timeout, int32_t *retval)
{
	int error = 0;
	u_int ni, nw;
	thread_t th_act;
	struct uthread  *uth;
	struct _select *sel;
	struct _select_data *seldata;
	int needzerofill = 1;
	int count = 0;
	size_t sz = 0;

	th_act = current_thread();
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_select;
	seldata = &uth->uu_save.uus_select_data;
	*retval = 0;

	seldata->args = uap;
	seldata->retval = retval;
	seldata->wqp = NULL;
	seldata->count = 0;

	if (uap->nd < 0) {
		return EINVAL;
	}

	/* select on thread of process that already called proc_exit() */
	if (p->p_fd == NULL) {
		return EBADF;
	}

	if (uap->nd > p->p_fd->fd_nfiles) {
		uap->nd = p->p_fd->fd_nfiles; /* forgiving; slightly wrong */
	}
	nw = howmany(uap->nd, NFDBITS);
	ni = nw * sizeof(fd_mask);

	/*
	 * if the previously allocated space for the bits is smaller than
	 * what is requested or no space has yet been allocated for this
	 * thread, allocate enough space now.
	 *
	 * Note: If this process fails, select() will return EAGAIN; this
	 * is the same thing pool() returns in a no-memory situation, but
	 * it is not a POSIX compliant error code for select().
	 */
	if (sel->nbytes < (3 * ni)) {
		int nbytes = 3 * ni;

		/* Free previous allocation, if any */
		if (sel->ibits != NULL) {
			FREE(sel->ibits, M_TEMP);
		}
		if (sel->obits != NULL) {
			FREE(sel->obits, M_TEMP);
			/* NULL out; subsequent ibits allocation may fail */
			sel->obits = NULL;
		}

		MALLOC(sel->ibits, u_int32_t *, nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if (sel->ibits == NULL) {
			return EAGAIN;
		}
		MALLOC(sel->obits, u_int32_t *, nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if (sel->obits == NULL) {
			FREE(sel->ibits, M_TEMP);
			sel->ibits = NULL;
			return EAGAIN;
		}
		sel->nbytes = nbytes;
		needzerofill = 0;
	}

	if (needzerofill) {
		bzero((caddr_t)sel->ibits, sel->nbytes);
		bzero((caddr_t)sel->obits, sel->nbytes);
	}

	/*
	 * get the bits from the user address space
	 */
#define getbits(name, x) \
	do { \
	        if (uap->name && (error = copyin(uap->name, \
	                (caddr_t)&sel->ibits[(x) * nw], ni))) \
	                goto continuation; \
	} while (0)

	getbits(in, 0);
	getbits(ou, 1);
	getbits(ex, 2);
#undef  getbits

	seldata->abstime = timeout;

	if ((error = selcount(p, sel->ibits, uap->nd, &count))) {
		goto continuation;
	}

	/*
	 * We need an array of waitq pointers. This is due to the new way
	 * in which waitqs are linked to sets. When a thread selects on a
	 * file descriptor, a waitq (embedded in a selinfo structure) is
	 * added to the thread's local waitq set. There is no longer any
	 * way to directly iterate over all members of a given waitq set.
	 * The process of linking a waitq into a set may allocate a link
	 * table object. Because we can't iterate over all the waitqs to
	 * which our thread waitq set belongs, we need a way of removing
	 * this link object!
	 *
	 * Thus we need a buffer which will hold one waitq pointer
	 * per FD being selected. During the tear-down phase we can use
	 * these pointers to dis-associate the underlying selinfo's waitq
	 * from our thread's waitq set.
	 *
	 * Because we also need to allocate a waitq set for this thread,
	 * we use a bare buffer pointer to hold all the memory. Note that
	 * this memory is cached in the thread pointer and not reaped until
	 * the thread exists. This is generally OK because threads that
	 * call select tend to keep calling select repeatedly.
	 */
	sz = ALIGN(sizeof(struct waitq_set)) + (count * sizeof(uint64_t));
	if (sz > uth->uu_wqstate_sz) {
		/* (re)allocate a buffer to hold waitq pointers */
		if (uth->uu_wqset) {
			if (waitq_set_is_valid(uth->uu_wqset)) {
				waitq_set_deinit(uth->uu_wqset);
			}
			FREE(uth->uu_wqset, M_SELECT);
		} else if (uth->uu_wqstate_sz && !uth->uu_wqset) {
			panic("select: thread structure corrupt! "
			    "uu_wqstate_sz:%ld, wqstate_buf == NULL",
			    uth->uu_wqstate_sz);
		}
		uth->uu_wqstate_sz = sz;
		MALLOC(uth->uu_wqset, struct waitq_set *, sz, M_SELECT, M_WAITOK);
		if (!uth->uu_wqset) {
			panic("can't allocate %ld bytes for wqstate buffer",
			    uth->uu_wqstate_sz);
		}
		waitq_set_init(uth->uu_wqset,
		    SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST, NULL, NULL);
	}

	if (!waitq_set_is_valid(uth->uu_wqset)) {
		waitq_set_init(uth->uu_wqset,
		    SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST, NULL, NULL);
	}

	/* the last chunk of our buffer is an array of waitq pointers */
	seldata->wqp = (uint64_t *)((char *)(uth->uu_wqset) + ALIGN(sizeof(struct waitq_set)));
	bzero(seldata->wqp, sz - ALIGN(sizeof(struct waitq_set)));

	seldata->count = count;

continuation:

	if (error) {
		/*
		 * We have already cleaned up any state we established,
		 * either locally or as a result of selcount().  We don't
		 * need to wait_subqueue_unlink_all(), since we haven't set
		 * anything at this point.
		 */
		return error;
	}

	return selprocess(0, SEL_FIRSTPASS);
}

int
selcontinue(int error)
{
	return selprocess(error, SEL_SECONDPASS);
}


/*
 * selprocess
 *
 * Parameters:	error			The error code from our caller
 *		sel_pass		The pass we are on
 */
int
selprocess(int error, int sel_pass)
{
	int ncoll;
	u_int ni, nw;
	thread_t th_act;
	struct uthread  *uth;
	struct proc *p;
	struct select_nocancel_args *uap;
	int *retval;
	struct _select *sel;
	struct _select_data *seldata;
	int unwind = 1;
	int prepost = 0;
	int somewakeup = 0;
	int doretry = 0;
	wait_result_t wait_result;

	p = current_proc();
	th_act = current_thread();
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_select;
	seldata = &uth->uu_save.uus_select_data;
	uap = seldata->args;
	retval = seldata->retval;

	if ((error != 0) && (sel_pass == SEL_FIRSTPASS)) {
		unwind = 0;
	}
	if (seldata->count == 0) {
		unwind = 0;
	}
retry:
	if (error != 0) {
		goto done;
	}

	ncoll = nselcoll;
	OSBitOrAtomic(P_SELECT, &p->p_flag);

	/* skip scans if the select is just for timeouts */
	if (seldata->count) {
		error = selscan(p, sel, seldata, uap->nd, retval, sel_pass, uth->uu_wqset);
		if (error || *retval) {
			goto done;
		}
		if (prepost || somewakeup) {
			/*
			 * if the select of log, then we can wakeup and
			 * discover some one else already read the data;
			 * go to select again if time permits
			 */
			prepost = 0;
			somewakeup = 0;
			doretry = 1;
		}
	}

	if (uap->tv) {
		uint64_t        now;

		clock_get_uptime(&now);
		if (now >= seldata->abstime) {
			goto done;
		}
	}

	if (doretry) {
		/* cleanup obits and try again */
		doretry = 0;
		sel_pass = SEL_FIRSTPASS;
		goto retry;
	}

	/*
	 * To effect a poll, the timeout argument should be
	 * non-nil, pointing to a zero-valued timeval structure.
	 */
	if (uap->tv && seldata->abstime == 0) {
		goto done;
	}

	/* No spurious wakeups due to colls,no need to check for them */
	if ((sel_pass == SEL_SECONDPASS) || ((p->p_flag & P_SELECT) == 0)) {
		sel_pass = SEL_FIRSTPASS;
		goto retry;
	}

	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);

	/* if the select is just for timeout skip check */
	if (seldata->count && (sel_pass == SEL_SECONDPASS)) {
		panic("selprocess: 2nd pass assertwaiting");
	}

	/* waitq_set has waitqueue as first element */
	wait_result = waitq_assert_wait64_leeway((struct waitq *)uth->uu_wqset,
	    NO_EVENT64, THREAD_ABORTSAFE,
	    TIMEOUT_URGENCY_USER_NORMAL,
	    seldata->abstime,
	    TIMEOUT_NO_LEEWAY);
	if (wait_result != THREAD_AWAKENED) {
		/* there are no preposted events */
		error = tsleep1(NULL, PSOCK | PCATCH,
		    "select", 0, selcontinue);
	} else {
		prepost = 1;
		error = 0;
	}

	if (error == 0) {
		sel_pass = SEL_SECONDPASS;
		if (!prepost) {
			somewakeup = 1;
		}
		goto retry;
	}
done:
	if (unwind) {
		seldrop(p, sel->ibits, uap->nd, seldata->count);
		waitq_set_deinit(uth->uu_wqset);
		/*
		 * zero out the waitq pointer array to avoid use-after free
		 * errors in the selcount error path (seldrop_locked) if/when
		 * the thread re-calls select().
		 */
		bzero((void *)uth->uu_wqset, uth->uu_wqstate_sz);
	}
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* select is not restarted after signals... */
	if (error == ERESTART) {
		error = EINTR;
	}
	if (error == EWOULDBLOCK) {
		error = 0;
	}
	nw = howmany(uap->nd, NFDBITS);
	ni = nw * sizeof(fd_mask);

#define putbits(name, x) \
	do { \
	        if (uap->name && (error2 = \
	                copyout((caddr_t)&sel->obits[(x) * nw], uap->name, ni))) \
	                error = error2; \
	} while (0)

	if (error == 0) {
		int error2;

		putbits(in, 0);
		putbits(ou, 1);
		putbits(ex, 2);
#undef putbits
	}

	if (error != EINTR && sel_pass == SEL_SECONDPASS && uth->uu_flag & UT_SAS_OLDMASK) {
		/* restore signal mask - continuation case */
		uth->uu_sigmask = uth->uu_oldmask;
		uth->uu_oldmask = 0;
		uth->uu_flag &= ~UT_SAS_OLDMASK;
	}

	return error;
}


/**
 * remove the fileproc's underlying waitq from the supplied waitq set;
 * clear FP_INSELECT when appropriate
 *
 * Parameters:
 *		fp	File proc that is potentially currently in select
 *		wqset	Waitq set to which the fileproc may belong
 *			(usually this is the thread's private waitq set)
 * Conditions:
 *		proc_fdlock is held
 */
static void
selunlinkfp(struct fileproc *fp, uint64_t wqp_id, struct waitq_set *wqset)
{
	int valid_set = waitq_set_is_valid(wqset);
	int valid_q = !!wqp_id;

	/*
	 * This could be called (from selcount error path) before we setup
	 * the thread's wqset. Check the wqset passed in, and only unlink if
	 * the set is valid.
	 */

	/* unlink the underlying waitq from the input set (thread waitq set) */
	if (valid_q && valid_set) {
		waitq_unlink_by_prepost_id(wqp_id, wqset);
	}

	/* allow passing a invalid fp for seldrop unwind */
	if (!(fp->fp_flags & (FP_INSELECT | FP_SELCONFLICT))) {
		return;
	}

	/*
	 * We can always remove the conflict queue from our thread's set: this
	 * will not affect other threads that potentially need to be awoken on
	 * the conflict queue during a fileproc_drain - those sets will still
	 * be linked with the global conflict queue, and the last waiter
	 * on the fp clears the CONFLICT marker.
	 */
	if (valid_set && (fp->fp_flags & FP_SELCONFLICT)) {
		waitq_unlink(&select_conflict_queue, wqset);
	}

	/* jca: TODO:
	 * This isn't quite right - we don't actually know if this
	 * fileproc is in another select or not! Here we just assume
	 * that if we were the first thread to select on the FD, then
	 * we'll be the one to clear this flag...
	 */
	if (valid_set && fp->fp_wset == (void *)wqset) {
		fp->fp_flags &= ~FP_INSELECT;
		fp->fp_wset = NULL;
	}
}

/**
 * connect a fileproc to the given wqset, potentially bridging to a waitq
 * pointed to indirectly by wq_data
 *
 * Parameters:
 *		fp	File proc potentially currently in select
 *		wq_data	Pointer to a pointer to a waitq (could be NULL)
 *		wqset	Waitq set to which the fileproc should now belong
 *			(usually this is the thread's private waitq set)
 *
 * Conditions:
 *		proc_fdlock is held
 */
static uint64_t
sellinkfp(struct fileproc *fp, void **wq_data, struct waitq_set *wqset)
{
	struct waitq *f_wq = NULL;

	if ((fp->fp_flags & FP_INSELECT) != FP_INSELECT) {
		if (wq_data) {
			panic("non-null data:%p on fp:%p not in select?!"
			    "(wqset:%p)", wq_data, fp, wqset);
		}
		return 0;
	}

	if ((fp->fp_flags & FP_SELCONFLICT) == FP_SELCONFLICT) {
		waitq_link(&select_conflict_queue, wqset, WAITQ_SHOULD_LOCK, NULL);
	}

	/*
	 * The wq_data parameter has potentially been set by selrecord called
	 * from a subsystems fo_select() function. If the subsystem does not
	 * call selrecord, then wq_data will be NULL
	 *
	 * Use memcpy to get the value into a proper pointer because
	 * wq_data most likely points to a stack variable that could be
	 * unaligned on 32-bit systems.
	 */
	if (wq_data) {
		memcpy(&f_wq, wq_data, sizeof(f_wq));
		if (!waitq_is_valid(f_wq)) {
			f_wq = NULL;
		}
	}

	/* record the first thread's wqset in the fileproc structure */
	if (!fp->fp_wset) {
		fp->fp_wset = (void *)wqset;
	}

	/* handles NULL f_wq */
	return waitq_get_prepost_id(f_wq);
}


/*
 * selscan
 *
 * Parameters:	p			Process performing the select
 *		sel			The per-thread select context structure
 *		nfd			The number of file descriptors to scan
 *		retval			The per thread system call return area
 *		sel_pass		Which pass this is; allowed values are
 *						SEL_FIRSTPASS and SEL_SECONDPASS
 *		wqset			The per thread wait queue set
 *
 * Returns:	0			Success
 *		EIO			Invalid p->p_fd field XXX Obsolete?
 *		EBADF			One of the files in the bit vector is
 *						invalid.
 */
static int
selscan(struct proc *p, struct _select *sel, struct _select_data * seldata,
    int nfd, int32_t *retval, int sel_pass, struct waitq_set *wqset)
{
	struct filedesc *fdp = p->p_fd;
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	int n = 0;              /* count of bits */
	int nc = 0;             /* bit vector offset (nc'th bit) */
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *optr;
	u_int nw;
	u_int32_t *ibits, *obits;
	uint64_t reserved_link, *rl_ptr = NULL;
	int count;
	struct vfs_context context = *vfs_context_current();

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*retval = 0;
		return EIO;
	}
	ibits = sel->ibits;
	obits = sel->obits;

	nw = howmany(nfd, NFDBITS);

	count = seldata->count;

	nc = 0;
	if (!count) {
		*retval = 0;
		return 0;
	}

	proc_fdlock(p);
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		optr = (u_int32_t *)&obits[msk * nw];

		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];

			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);

				fp = fp_get_noref_locked(p, fd);
				if (fp == NULL) {
					/*
					 * If we abort because of a bad
					 * fd, let the caller unwind...
					 */
					proc_fdunlock(p);
					return EBADF;
				}
				if (sel_pass == SEL_SECONDPASS) {
					reserved_link = 0;
					rl_ptr = NULL;
					selunlinkfp(fp, seldata->wqp[nc], wqset);
				} else {
					reserved_link = waitq_link_reserve((struct waitq *)wqset);
					rl_ptr = &reserved_link;
					if (fp->fp_flags & FP_INSELECT) {
						/* someone is already in select on this fp */
						fp->fp_flags |= FP_SELCONFLICT;
					} else {
						fp->fp_flags |= FP_INSELECT;
					}

					waitq_set_lazy_init_link(wqset);
				}

				context.vc_ucred = fp->f_cred;

				/*
				 * stash this value b/c fo_select may replace
				 * reserved_link with a pointer to a waitq object
				 */
				uint64_t rsvd = reserved_link;

				/* The select; set the bit, if true */
				if (fp->f_ops && fp->f_type
				    && fo_select(fp, flag[msk], rl_ptr, &context)) {
					optr[fd / NFDBITS] |= (1U << (fd % NFDBITS));
					n++;
				}
				if (sel_pass == SEL_FIRSTPASS) {
					waitq_link_release(rsvd);
					/*
					 * If the fp's supporting selinfo structure was linked
					 * to this thread's waitq set, then 'reserved_link'
					 * will have been updated by selrecord to be a pointer
					 * to the selinfo's waitq.
					 */
					if (reserved_link == rsvd) {
						rl_ptr = NULL; /* fo_select never called selrecord() */
					}
					/*
					 * Hook up the thread's waitq set either to
					 * the fileproc structure, or to the global
					 * conflict queue: but only on the first
					 * select pass.
					 */
					seldata->wqp[nc] = sellinkfp(fp, (void **)rl_ptr, wqset);
				}
				nc++;
			}
		}
	}
	proc_fdunlock(p);

	*retval = n;
	return 0;
}

static int poll_callback(struct kevent_qos_s *, kevent_ctx_t);

int
poll(struct proc *p, struct poll_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return poll_nocancel(p, (struct poll_nocancel_args *)uap, retval);
}


int
poll_nocancel(struct proc *p, struct poll_nocancel_args *uap, int32_t *retval)
{
	struct pollfd *fds = NULL;
	struct kqueue *kq = NULL;
	int ncoll, error = 0;
	u_int nfds = uap->nfds;
	u_int rfds = 0;
	rlim_t nofile = proc_limitgetcur(p, RLIMIT_NOFILE, TRUE);

	/*
	 * This is kinda bogus.  We have fd limits, but that is not
	 * really related to the size of the pollfd array.  Make sure
	 * we let the process use at least FD_SETSIZE entries and at
	 * least enough for the current limits.  We want to be reasonably
	 * safe, but not overly restrictive.
	 */
	if (nfds > OPEN_MAX ||
	    (nfds > nofile && (proc_suser(p) || nfds > FD_SETSIZE))) {
		return EINVAL;
	}

	kq = kqueue_alloc(p);
	if (kq == NULL) {
		return EAGAIN;
	}

	if (nfds) {
		size_t ni = nfds * sizeof(struct pollfd);
		MALLOC(fds, struct pollfd *, ni, M_TEMP, M_WAITOK);
		if (NULL == fds) {
			error = EAGAIN;
			goto out;
		}

		error = copyin(uap->fds, fds, nfds * sizeof(struct pollfd));
		if (error) {
			goto out;
		}
	}

	/* JMM - all this P_SELECT stuff is bogus */
	ncoll = nselcoll;
	OSBitOrAtomic(P_SELECT, &p->p_flag);
	for (u_int i = 0; i < nfds; i++) {
		short events = fds[i].events;
		__assert_only int rc;

		/* per spec, ignore fd values below zero */
		if (fds[i].fd < 0) {
			fds[i].revents = 0;
			continue;
		}

		/* convert the poll event into a kqueue kevent */
		struct kevent_qos_s kev = {
			.ident = fds[i].fd,
			.flags = EV_ADD | EV_ONESHOT | EV_POLL,
			.udata = CAST_USER_ADDR_T(&fds[i])
		};

		/* Handle input events */
		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND | POLLHUP)) {
			kev.filter = EVFILT_READ;
			if (events & (POLLPRI | POLLRDBAND)) {
				kev.flags |= EV_OOBAND;
			}
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		/* Handle output events */
		if ((kev.flags & EV_ERROR) == 0 &&
		    (events & (POLLOUT | POLLWRNORM | POLLWRBAND))) {
			kev.filter = EVFILT_WRITE;
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		/* Handle BSD extension vnode events */
		if ((kev.flags & EV_ERROR) == 0 &&
		    (events & (POLLEXTEND | POLLATTRIB | POLLNLINK | POLLWRITE))) {
			kev.filter = EVFILT_VNODE;
			kev.fflags = 0;
			if (events & POLLEXTEND) {
				kev.fflags |= NOTE_EXTEND;
			}
			if (events & POLLATTRIB) {
				kev.fflags |= NOTE_ATTRIB;
			}
			if (events & POLLNLINK) {
				kev.fflags |= NOTE_LINK;
			}
			if (events & POLLWRITE) {
				kev.fflags |= NOTE_WRITE;
			}
			rc = kevent_register(kq, &kev, NULL);
			assert((rc & FILTER_REGISTER_WAIT) == 0);
		}

		if (kev.flags & EV_ERROR) {
			fds[i].revents = POLLNVAL;
			rfds++;
		} else {
			fds[i].revents = 0;
		}
	}

	/*
	 * Did we have any trouble registering?
	 * If user space passed 0 FDs, then respect any timeout value passed.
	 * This is an extremely inefficient sleep. If user space passed one or
	 * more FDs, and we had trouble registering _all_ of them, then bail
	 * out. If a subset of the provided FDs failed to register, then we
	 * will still call the kqueue_scan function.
	 */
	if (nfds && (rfds == nfds)) {
		goto done;
	}

	/* scan for, and possibly wait for, the kevents to trigger */
	kevent_ctx_t kectx = kevent_get_context(current_thread());
	*kectx = (struct kevent_ctx_s){
		.kec_process_noutputs = rfds,
		.kec_process_flags    = KEVENT_FLAG_POLL,
		.kec_deadline         = 0, /* wait forever */
	};

	/*
	 * If any events have trouble registering, an event has fired and we
	 * shouldn't wait for events in kqueue_scan.
	 */
	if (rfds) {
		kectx->kec_process_flags |= KEVENT_FLAG_IMMEDIATE;
	} else if (uap->timeout != -1) {
		clock_interval_to_deadline(uap->timeout, NSEC_PER_MSEC,
		    &kectx->kec_deadline);
	}

	error = kqueue_scan(kq, kectx->kec_process_flags, kectx, poll_callback);
	rfds = kectx->kec_process_noutputs;

done:
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* poll is not restarted after signals... */
	if (error == ERESTART) {
		error = EINTR;
	}
	if (error == 0) {
		error = copyout(fds, uap->fds, nfds * sizeof(struct pollfd));
		*retval = rfds;
	}

out:
	if (NULL != fds) {
		FREE(fds, M_TEMP);
	}

	kqueue_dealloc(kq);
	return error;
}

static int
poll_callback(struct kevent_qos_s *kevp, kevent_ctx_t kectx)
{
	struct pollfd *fds = CAST_DOWN(struct pollfd *, kevp->udata);
	short prev_revents = fds->revents;
	short mask = 0;

	/* convert the results back into revents */
	if (kevp->flags & EV_EOF) {
		fds->revents |= POLLHUP;
	}
	if (kevp->flags & EV_ERROR) {
		fds->revents |= POLLERR;
	}

	switch (kevp->filter) {
	case EVFILT_READ:
		if (fds->revents & POLLHUP) {
			mask = (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND);
		} else {
			mask = (POLLIN | POLLRDNORM);
			if (kevp->flags & EV_OOBAND) {
				mask |= (POLLPRI | POLLRDBAND);
			}
		}
		fds->revents |= (fds->events & mask);
		break;

	case EVFILT_WRITE:
		if (!(fds->revents & POLLHUP)) {
			fds->revents |= (fds->events & (POLLOUT | POLLWRNORM | POLLWRBAND));
		}
		break;

	case EVFILT_VNODE:
		if (kevp->fflags & NOTE_EXTEND) {
			fds->revents |= (fds->events & POLLEXTEND);
		}
		if (kevp->fflags & NOTE_ATTRIB) {
			fds->revents |= (fds->events & POLLATTRIB);
		}
		if (kevp->fflags & NOTE_LINK) {
			fds->revents |= (fds->events & POLLNLINK);
		}
		if (kevp->fflags & NOTE_WRITE) {
			fds->revents |= (fds->events & POLLWRITE);
		}
		break;
	}

	if (fds->revents != 0 && prev_revents == 0) {
		kectx->kec_process_noutputs++;
	}

	return 0;
}

int
seltrue(__unused dev_t dev, __unused int flag, __unused struct proc *p)
{
	return 1;
}

/*
 * selcount
 *
 * Count the number of bits set in the input bit vector, and establish an
 * outstanding fp->fp_iocount for each of the descriptors which will be in
 * use in the select operation.
 *
 * Parameters:	p			The process doing the select
 *		ibits			The input bit vector
 *		nfd			The number of fd's in the vector
 *		countp			Pointer to where to store the bit count
 *
 * Returns:	0			Success
 *		EIO			Bad per process open file table
 *		EBADF			One of the bits in the input bit vector
 *						references an invalid fd
 *
 * Implicit:	*countp (modified)	Count of fd's
 *
 * Notes:	This function is the first pass under the proc_fdlock() that
 *		permits us to recognize invalid descriptors in the bit vector;
 *		the may, however, not remain valid through the drop and
 *		later reacquisition of the proc_fdlock().
 */
static int
selcount(struct proc *p, u_int32_t *ibits, int nfd, int *countp)
{
	struct filedesc *fdp = p->p_fd;
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	int n = 0;
	u_int32_t *iptr;
	u_int nw;
	int error = 0;
	int need_wakeup = 0;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*countp = 0;
		return EIO;
	}
	nw = howmany(nfd, NFDBITS);

	proc_fdlock(p);
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);

				fp = fp_get_noref_locked(p, fd);
				if (fp == NULL) {
					*countp = 0;
					error = EBADF;
					goto bad;
				}
				os_ref_retain_locked(&fp->fp_iocount);
				n++;
			}
		}
	}
	proc_fdunlock(p);

	*countp = n;
	return 0;

bad:
	if (n == 0) {
		goto out;
	}
	/* Ignore error return; it's already EBADF */
	(void)seldrop_locked(p, ibits, nfd, n, &need_wakeup);

out:
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fpdrainwait);
	}
	return error;
}


/*
 * seldrop_locked
 *
 * Drop outstanding wait queue references set up during selscan(); drop the
 * outstanding per fileproc fp_iocount picked up during the selcount().
 *
 * Parameters:	p			Process performing the select
 *		ibits			Input bit bector of fd's
 *		nfd			Number of fd's
 *		lim			Limit to number of vector entries to
 *						consider, or -1 for "all"
 *		inselect		True if
 *		need_wakeup		Pointer to flag to set to do a wakeup
 *					if f_iocont on any descriptor goes to 0
 *
 * Returns:	0			Success
 *		EBADF			One or more fds in the bit vector
 *						were invalid, but the rest
 *						were successfully dropped
 *
 * Notes:	An fd make become bad while the proc_fdlock() is not held,
 *		if a multithreaded application closes the fd out from under
 *		the in progress select.  In this case, we still have to
 *		clean up after the set up on the remaining fds.
 */
static int
seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup)
{
	struct filedesc *fdp = p->p_fd;
	int msk, i, j, nc, fd;
	u_int32_t bits;
	struct fileproc *fp;
	u_int32_t *iptr;
	u_int nw;
	int error = 0;
	uthread_t uth = get_bsdthread_info(current_thread());
	struct _select_data *seldata;

	*need_wakeup = 0;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		return EIO;
	}

	nw = howmany(nfd, NFDBITS);
	seldata = &uth->uu_save.uus_select_data;

	nc = 0;
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i / NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1U << j);
				/*
				 * If we've already dropped as many as were
				 * counted/scanned, then we are done.
				 */
				if (nc >= lim) {
					goto done;
				}

				/*
				 * We took an I/O reference in selcount,
				 * so the fp can't possibly be NULL.
				 */
				fp = fp_get_noref_locked_with_iocount(p, fd);
				selunlinkfp(fp,
				    seldata->wqp ? seldata->wqp[nc] : 0,
				    uth->uu_wqset);

				nc++;

				const os_ref_count_t refc = os_ref_release_locked(&fp->fp_iocount);
				if (0 == refc) {
					panic("fp_iocount overdecrement!");
				}

				if (1 == refc) {
					/*
					 * The last iocount is responsible for clearing
					 * selconfict flag - even if we didn't set it -
					 * and is also responsible for waking up anyone
					 * waiting on iocounts to drain.
					 */
					if (fp->fp_flags & FP_SELCONFLICT) {
						fp->fp_flags &= ~FP_SELCONFLICT;
					}
					if (p->p_fpdrainwait) {
						p->p_fpdrainwait = 0;
						*need_wakeup = 1;
					}
				}
			}
		}
	}
done:
	return error;
}


static int
seldrop(struct proc *p, u_int32_t *ibits, int nfd, int lim)
{
	int error;
	int need_wakeup = 0;

	proc_fdlock(p);
	error = seldrop_locked(p, ibits, nfd, lim, &need_wakeup);
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fpdrainwait);
	}
	return error;
}

/*
 * Record a select request.
 */
void
selrecord(__unused struct proc *selector, struct selinfo *sip, void *s_data)
{
	thread_t        cur_act = current_thread();
	struct uthread * ut = get_bsdthread_info(cur_act);
	/* on input, s_data points to the 64-bit ID of a reserved link object */
	uint64_t *reserved_link = (uint64_t *)s_data;

	/* need to look at collisions */

	/*do not record if this is second pass of select */
	if (!s_data) {
		return;
	}

	if ((sip->si_flags & SI_INITED) == 0) {
		waitq_init(&sip->si_waitq, SYNC_POLICY_FIFO);
		sip->si_flags |= SI_INITED;
		sip->si_flags &= ~SI_CLEAR;
	}

	if (sip->si_flags & SI_RECORDED) {
		sip->si_flags |= SI_COLL;
	} else {
		sip->si_flags &= ~SI_COLL;
	}

	sip->si_flags |= SI_RECORDED;
	/* note: this checks for pre-existing linkage */
	waitq_link(&sip->si_waitq, ut->uu_wqset,
	    WAITQ_SHOULD_LOCK, reserved_link);

	/*
	 * Always consume the reserved link.
	 * We can always call waitq_link_release() safely because if
	 * waitq_link is successful, it consumes the link and resets the
	 * value to 0, in which case our call to release becomes a no-op.
	 * If waitq_link fails, then the following release call will actually
	 * release the reserved link object.
	 */
	waitq_link_release(*reserved_link);
	*reserved_link = 0;

	/*
	 * Use the s_data pointer as an output parameter as well
	 * This avoids changing the prototype for this function which is
	 * used by many kexts. We need to surface the waitq object
	 * associated with the selinfo we just added to the thread's select
	 * set. New waitq sets do not have back-pointers to set members, so
	 * the only way to clear out set linkage objects is to go from the
	 * waitq to the set. We use a memcpy because s_data could be
	 * pointing to an unaligned value on the stack
	 * (especially on 32-bit systems)
	 */
	void *wqptr = (void *)&sip->si_waitq;
	memcpy((void *)s_data, (void *)&wqptr, sizeof(void *));

	return;
}

void
selwakeup(struct selinfo *sip)
{
	if ((sip->si_flags & SI_INITED) == 0) {
		return;
	}

	if (sip->si_flags & SI_COLL) {
		nselcoll++;
		sip->si_flags &= ~SI_COLL;
#if 0
		/* will not  support */
		//wakeup((caddr_t)&selwait);
#endif
	}

	if (sip->si_flags & SI_RECORDED) {
		waitq_wakeup64_all(&sip->si_waitq, NO_EVENT64,
		    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
		sip->si_flags &= ~SI_RECORDED;
	}
}

void
selthreadclear(struct selinfo *sip)
{
	struct waitq *wq;

	if ((sip->si_flags & SI_INITED) == 0) {
		return;
	}
	if (sip->si_flags & SI_RECORDED) {
		selwakeup(sip);
		sip->si_flags &= ~(SI_RECORDED | SI_COLL);
	}
	sip->si_flags |= SI_CLEAR;
	sip->si_flags &= ~SI_INITED;

	wq = &sip->si_waitq;

	/*
	 * Higher level logic may have a handle on this waitq's prepost ID,
	 * but that's OK because the waitq_deinit will remove/invalidate the
	 * prepost object (as well as mark the waitq invalid). This de-couples
	 * us from any callers that may have a handle to this waitq via the
	 * prepost ID.
	 */
	waitq_deinit(wq);
}


/*
 * gethostuuid
 *
 * Description:	Get the host UUID from IOKit and return it to user space.
 *
 * Parameters:	uuid_buf		Pointer to buffer to receive UUID
 *		timeout			Timespec for timout
 *
 * Returns:	0			Success
 *		EWOULDBLOCK		Timeout is too short
 *		copyout:EFAULT		Bad user buffer
 *		mac_system_check_info:EPERM		Client not allowed to perform this operation
 *
 * Notes:	A timeout seems redundant, since if it's tolerable to not
 *		have a system UUID in hand, then why ask for one?
 */
int
gethostuuid(struct proc *p, struct gethostuuid_args *uap, __unused int32_t *retval)
{
	kern_return_t kret;
	int error;
	mach_timespec_t mach_ts;        /* for IOKit call */
	__darwin_uuid_t uuid_kern = {}; /* for IOKit call */

	/* Check entitlement */
	if (!IOTaskHasEntitlement(current_task(), "com.apple.private.getprivatesysid")) {
#if !defined(XNU_TARGET_OS_OSX)
#if CONFIG_MACF
		if ((error = mac_system_check_info(kauth_cred_get(), "hw.uuid")) != 0) {
			/* EPERM invokes userspace upcall if present */
			return error;
		}
#endif
#endif
	}

	/* Convert the 32/64 bit timespec into a mach_timespec_t */
	if (proc_is64bit(p)) {
		struct user64_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts));
		if (error) {
			return error;
		}
		mach_ts.tv_sec = (unsigned int)ts.tv_sec;
		mach_ts.tv_nsec = (clock_res_t)ts.tv_nsec;
	} else {
		struct user32_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts));
		if (error) {
			return error;
		}
		mach_ts.tv_sec = ts.tv_sec;
		mach_ts.tv_nsec = ts.tv_nsec;
	}

	/* Call IOKit with the stack buffer to get the UUID */
	kret = IOBSDGetPlatformUUID(uuid_kern, mach_ts);

	/*
	 * If we get it, copy out the data to the user buffer; note that a
	 * uuid_t is an array of characters, so this is size invariant for
	 * 32 vs. 64 bit.
	 */
	if (kret == KERN_SUCCESS) {
		error = copyout(uuid_kern, uap->uuid_buf, sizeof(uuid_kern));
	} else {
		error = EWOULDBLOCK;
	}

	return error;
}

/*
 * ledger
 *
 * Description:	Omnibus system call for ledger operations
 */
int
ledger(struct proc *p, struct ledger_args *args, __unused int32_t *retval)
{
#if !CONFIG_MACF
#pragma unused(p)
#endif
	int rval, pid, len, error;
#ifdef LEDGER_DEBUG
	struct ledger_limit_args lla;
#endif
	task_t task;
	proc_t proc;

	/* Finish copying in the necessary args before taking the proc lock */
	error = 0;
	len = 0;
	if (args->cmd == LEDGER_ENTRY_INFO) {
		error = copyin(args->arg3, (char *)&len, sizeof(len));
	} else if (args->cmd == LEDGER_TEMPLATE_INFO) {
		error = copyin(args->arg2, (char *)&len, sizeof(len));
	} else if (args->cmd == LEDGER_LIMIT)
#ifdef LEDGER_DEBUG
	{ error = copyin(args->arg2, (char *)&lla, sizeof(lla));}
#else
	{ return EINVAL; }
#endif
	else if ((args->cmd < 0) || (args->cmd > LEDGER_MAX_CMD)) {
		return EINVAL;
	}

	if (error) {
		return error;
	}
	if (len < 0) {
		return EINVAL;
	}

	rval = 0;
	if (args->cmd != LEDGER_TEMPLATE_INFO) {
		pid = (int)args->arg1;
		proc = proc_find(pid);
		if (proc == NULL) {
			return ESRCH;
		}

#if CONFIG_MACF
		error = mac_proc_check_ledger(p, proc, args->cmd);
		if (error) {
			proc_rele(proc);
			return error;
		}
#endif

		task = proc->task;
	}

	switch (args->cmd) {
#ifdef LEDGER_DEBUG
	case LEDGER_LIMIT: {
		if (!kauth_cred_issuser(kauth_cred_get())) {
			rval = EPERM;
		}
		rval = ledger_limit(task, &lla);
		proc_rele(proc);
		break;
	}
#endif
	case LEDGER_INFO: {
		struct ledger_info info = {};

		rval = ledger_info(task, &info);
		proc_rele(proc);
		if (rval == 0) {
			rval = copyout(&info, args->arg2,
			    sizeof(info));
		}
		break;
	}

	case LEDGER_ENTRY_INFO: {
		void *buf;
		int sz;

		rval = ledger_get_task_entry_info_multiple(task, &buf, &len);
		proc_rele(proc);
		if ((rval == 0) && (len >= 0)) {
			sz = len * sizeof(struct ledger_entry_info);
			rval = copyout(buf, args->arg2, sz);
			kheap_free(KHEAP_DATA_BUFFERS, buf, sz);
		}
		if (rval == 0) {
			rval = copyout(&len, args->arg3, sizeof(len));
		}
		break;
	}

	case LEDGER_TEMPLATE_INFO: {
		void *buf;
		int sz;

		rval = ledger_template_info(&buf, &len);
		if ((rval == 0) && (len >= 0)) {
			sz = len * sizeof(struct ledger_template_info);
			rval = copyout(buf, args->arg1, sz);
			kheap_free(KHEAP_DATA_BUFFERS, buf, sz);
		}
		if (rval == 0) {
			rval = copyout(&len, args->arg2, sizeof(len));
		}
		break;
	}

	default:
		panic("ledger syscall logic error -- command type %d", args->cmd);
		proc_rele(proc);
		rval = EINVAL;
	}

	return rval;
}

int
telemetry(__unused struct proc *p, struct telemetry_args *args, __unused int32_t *retval)
{
	int error = 0;

	switch (args->cmd) {
#if CONFIG_TELEMETRY
	case TELEMETRY_CMD_TIMER_EVENT:
		error = telemetry_timer_event(args->deadline, args->interval, args->leeway);
		break;
	case TELEMETRY_CMD_PMI_SETUP:
		error = telemetry_pmi_setup((enum telemetry_pmi)args->deadline, args->interval);
		break;
#endif /* CONFIG_TELEMETRY */
	case TELEMETRY_CMD_VOUCHER_NAME:
		if (thread_set_voucher_name((mach_port_name_t)args->deadline)) {
			error = EINVAL;
		}
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

/*
 * Logging
 *
 * Description: syscall to access kernel logging from userspace
 *
 * Args:
 *	tag - used for syncing with userspace on the version.
 *	flags - flags used by the syscall.
 *	buffer - userspace address of string to copy.
 *	size - size of buffer.
 */
int
log_data(__unused struct proc *p, struct log_data_args *args, int *retval)
{
	unsigned int tag = args->tag;
	unsigned int flags = args->flags;
	user_addr_t buffer = args->buffer;
	unsigned int size = args->size;
	int ret = 0;
	char *log_msg = NULL;
	int error;
	*retval = 0;

	/*
	 * Tag synchronize the syscall version with userspace.
	 * Tag == 0 => flags == OS_LOG_TYPE
	 */
	if (tag != 0) {
		return EINVAL;
	}

	/*
	 * OS_LOG_TYPE are defined in libkern/os/log.h
	 * In userspace they are defined in libtrace/os/log.h
	 */
	if (flags != OS_LOG_TYPE_DEFAULT &&
	    flags != OS_LOG_TYPE_INFO &&
	    flags != OS_LOG_TYPE_DEBUG &&
	    flags != OS_LOG_TYPE_ERROR &&
	    flags != OS_LOG_TYPE_FAULT) {
		return EINVAL;
	}

	if (size == 0) {
		return EINVAL;
	}

	/* truncate to OS_LOG_DATA_MAX_SIZE */
	if (size > OS_LOG_DATA_MAX_SIZE) {
		printf("%s: WARNING msg is going to be truncated from %u to %u\n",
		    __func__, size, OS_LOG_DATA_MAX_SIZE);
		size = OS_LOG_DATA_MAX_SIZE;
	}

	log_msg = kheap_alloc(KHEAP_TEMP, size, Z_WAITOK);
	if (!log_msg) {
		return ENOMEM;
	}

	error = copyin(buffer, log_msg, size);
	if (error) {
		ret = EFAULT;
		goto out;
	}
	log_msg[size - 1] = '\0';

	/*
	 * This will log to dmesg and logd.
	 * The call will fail if the current
	 * process is not a driverKit process.
	 */
	os_log_driverKit(&ret, OS_LOG_DEFAULT, (os_log_type_t)flags, "%s", log_msg);

out:
	if (log_msg != NULL) {
		kheap_free(KHEAP_TEMP, log_msg, size);
	}

	return ret;
}

#if DEVELOPMENT || DEBUG
#if CONFIG_WAITQ_DEBUG
static uint64_t g_wqset_num = 0;
struct g_wqset {
	queue_chain_t      link;
	struct waitq_set  *wqset;
};

static queue_head_t         g_wqset_list;
static struct waitq_set    *g_waitq_set = NULL;

static inline struct waitq_set *
sysctl_get_wqset(int idx)
{
	struct g_wqset *gwqs;

	if (!g_wqset_num) {
		queue_init(&g_wqset_list);
	}

	/* don't bother with locks: this is test-only code! */
	qe_foreach_element(gwqs, &g_wqset_list, link) {
		if ((int)(wqset_id(gwqs->wqset) & 0xffffffff) == idx) {
			return gwqs->wqset;
		}
	}

	/* allocate a new one */
	++g_wqset_num;
	gwqs = (struct g_wqset *)kalloc(sizeof(*gwqs));
	assert(gwqs != NULL);

	gwqs->wqset = waitq_set_alloc(SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST, NULL);
	enqueue_tail(&g_wqset_list, &gwqs->link);
	printf("[WQ]: created new waitq set 0x%llx\n", wqset_id(gwqs->wqset));

	return gwqs->wqset;
}

#define MAX_GLOBAL_TEST_QUEUES 64
static int g_wq_init = 0;
static struct waitq  g_wq[MAX_GLOBAL_TEST_QUEUES];

static inline struct waitq *
global_test_waitq(int idx)
{
	if (idx < 0) {
		return NULL;
	}

	if (!g_wq_init) {
		g_wq_init = 1;
		for (int i = 0; i < MAX_GLOBAL_TEST_QUEUES; i++) {
			waitq_init(&g_wq[i], SYNC_POLICY_FIFO);
		}
	}

	return &g_wq[idx % MAX_GLOBAL_TEST_QUEUES];
}

static int sysctl_waitq_wakeup_one SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int index;
	struct waitq *waitq;
	kern_return_t kr;
	int64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (event64 < 0) {
		index = (int)((-event64) & 0xffffffff);
		waitq = wqset_waitq(sysctl_get_wqset(index));
		index = -index;
	} else {
		index = (int)event64;
		waitq = global_test_waitq(index);
	}

	event64 = 0;

	printf("[WQ]: Waking one thread on waitq [%d] event:0x%llx\n",
	    index, event64);
	kr = waitq_wakeup64_one(waitq, (event64_t)event64, THREAD_AWAKENED,
	    WAITQ_ALL_PRIORITIES);
	printf("[WQ]: \tkr=%d\n", kr);

	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_wakeup_one, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_wakeup_one, "Q", "wakeup one thread waiting on given event");


static int sysctl_waitq_wakeup_all SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int index;
	struct waitq *waitq;
	kern_return_t kr;
	int64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (event64 < 0) {
		index = (int)((-event64) & 0xffffffff);
		waitq = wqset_waitq(sysctl_get_wqset(index));
		index = -index;
	} else {
		index = (int)event64;
		waitq = global_test_waitq(index);
	}

	event64 = 0;

	printf("[WQ]: Waking all threads on waitq [%d] event:0x%llx\n",
	    index, event64);
	kr = waitq_wakeup64_all(waitq, (event64_t)event64,
	    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
	printf("[WQ]: \tkr=%d\n", kr);

	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_wakeup_all, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_wakeup_all, "Q", "wakeup all threads waiting on given event");


static int sysctl_waitq_wait SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int index;
	struct waitq *waitq;
	kern_return_t kr;
	int64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (event64 < 0) {
		index = (int)((-event64) & 0xffffffff);
		waitq = wqset_waitq(sysctl_get_wqset(index));
		index = -index;
	} else {
		index = (int)event64;
		waitq = global_test_waitq(index);
	}

	event64 = 0;

	printf("[WQ]: Current thread waiting on waitq [%d] event:0x%llx\n",
	    index, event64);
	kr = waitq_assert_wait64(waitq, (event64_t)event64, THREAD_INTERRUPTIBLE, 0);
	if (kr == THREAD_WAITING) {
		thread_block(THREAD_CONTINUE_NULL);
	}
	printf("[WQ]: \tWoke Up: kr=%d\n", kr);

	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_wait, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_wait, "Q", "start waiting on given event");


static int sysctl_wqset_select SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	struct waitq_set *wqset;
	uint64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		goto out;
	}

	wqset = sysctl_get_wqset((int)(event64 & 0xffffffff));
	g_waitq_set = wqset;

	event64 = wqset_id(wqset);
	printf("[WQ]: selected wqset 0x%llx\n", event64);

out:
	if (g_waitq_set) {
		event64 = wqset_id(g_waitq_set);
	} else {
		event64 = (uint64_t)(-1);
	}

	return SYSCTL_OUT(req, &event64, sizeof(event64));
}
SYSCTL_PROC(_kern, OID_AUTO, wqset_select, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_wqset_select, "Q", "select/create a global waitq set");


static int sysctl_waitq_link SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int index;
	struct waitq *waitq;
	struct waitq_set *wqset;
	kern_return_t kr;
	uint64_t reserved_link = 0;
	int64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (!g_waitq_set) {
		g_waitq_set = sysctl_get_wqset(1);
	}
	wqset = g_waitq_set;

	if (event64 < 0) {
		struct waitq_set *tmp;
		index = (int)((-event64) & 0xffffffff);
		tmp = sysctl_get_wqset(index);
		if (tmp == wqset) {
			goto out;
		}
		waitq = wqset_waitq(tmp);
		index = -index;
	} else {
		index = (int)event64;
		waitq = global_test_waitq(index);
	}

	printf("[WQ]: linking waitq [%d] to global wqset (0x%llx)\n",
	    index, wqset_id(wqset));
	reserved_link = waitq_link_reserve(waitq);
	kr = waitq_link(waitq, wqset, WAITQ_SHOULD_LOCK, &reserved_link);
	waitq_link_release(reserved_link);

	printf("[WQ]: \tkr=%d\n", kr);

out:
	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_link, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_link, "Q", "link global waitq to test waitq set");


static int sysctl_waitq_unlink SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int index;
	struct waitq *waitq;
	struct waitq_set *wqset;
	kern_return_t kr;
	uint64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (!g_waitq_set) {
		g_waitq_set = sysctl_get_wqset(1);
	}
	wqset = g_waitq_set;

	index = (int)event64;
	waitq = global_test_waitq(index);

	printf("[WQ]: unlinking waitq [%d] from global wqset (0x%llx)\n",
	    index, wqset_id(wqset));

	kr = waitq_unlink(waitq, wqset);
	printf("[WQ]: \tkr=%d\n", kr);

	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_unlink, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_unlink, "Q", "unlink global waitq from test waitq set");


static int sysctl_waitq_clear_prepost SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct waitq *waitq;
	uint64_t event64 = 0;
	int error, index;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	index = (int)event64;
	waitq = global_test_waitq(index);

	printf("[WQ]: clearing prepost on waitq [%d]\n", index);
	waitq_clear_prepost(waitq);

	return SYSCTL_OUT(req, &event64, sizeof(event64));
}
SYSCTL_PROC(_kern, OID_AUTO, waitq_clear_prepost, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_clear_prepost, "Q", "clear prepost on given waitq");


static int sysctl_wqset_unlink_all SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	struct waitq_set *wqset;
	kern_return_t kr;
	uint64_t event64 = 0;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return SYSCTL_OUT(req, &event64, sizeof(event64));
	}

	if (!g_waitq_set) {
		g_waitq_set = sysctl_get_wqset(1);
	}
	wqset = g_waitq_set;

	printf("[WQ]: unlinking all queues from global wqset (0x%llx)\n",
	    wqset_id(wqset));

	kr = waitq_set_unlink_all(wqset);
	printf("[WQ]: \tkr=%d\n", kr);

	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, wqset_unlink_all, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_wqset_unlink_all, "Q", "unlink all queues from test waitq set");


static int sysctl_wqset_clear_preposts SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct waitq_set *wqset = NULL;
	uint64_t event64 = 0;
	int error, index;

	error = SYSCTL_IN(req, &event64, sizeof(event64));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		goto out;
	}

	index = (int)((event64) & 0xffffffff);
	wqset = sysctl_get_wqset(index);
	assert(wqset != NULL);

	printf("[WQ]: clearing preposts on wqset 0x%llx\n", wqset_id(wqset));
	waitq_set_clear_preposts(wqset);

out:
	if (wqset) {
		event64 = wqset_id(wqset);
	} else {
		event64 = (uint64_t)(-1);
	}

	return SYSCTL_OUT(req, &event64, sizeof(event64));
}
SYSCTL_PROC(_kern, OID_AUTO, wqset_clear_preposts, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_wqset_clear_preposts, "Q", "clear preposts on given waitq set");

#endif /* CONFIG_WAITQ_DEBUG */

static int
sysctl_waitq_set_nelem SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int nelem;

	/* Read only  */
	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}

	nelem = sysctl_helper_waitq_set_nelem();

	return SYSCTL_OUT(req, &nelem, sizeof(nelem));
}

SYSCTL_PROC(_kern, OID_AUTO, n_ltable_entries, CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_waitq_set_nelem, "I", "ltable elementis currently used");


static int
sysctl_mpsc_test_pingpong SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t value = 0;
	int error;

	error = SYSCTL_IN(req, &value, sizeof(value));
	if (error) {
		return error;
	}

	if (error == 0 && req->newptr) {
		error = mpsc_test_pingpong(value, &value);
		if (error == 0) {
			error = SYSCTL_OUT(req, &value, sizeof(value));
		}
	}

	return error;
}
SYSCTL_PROC(_kern, OID_AUTO, mpsc_test_pingpong, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mpsc_test_pingpong, "Q", "MPSC tests: pingpong");

#endif /* DEVELOPMENT || DEBUG */

/*Remote Time api*/
SYSCTL_NODE(_machdep, OID_AUTO, remotetime, CTLFLAG_RD | CTLFLAG_LOCKED, 0, "Remote time api");

#if DEVELOPMENT || DEBUG
#if CONFIG_MACH_BRIDGE_SEND_TIME
extern _Atomic uint32_t bt_init_flag;
extern uint32_t mach_bridge_timer_enable(uint32_t, int);

SYSCTL_INT(_machdep_remotetime, OID_AUTO, bridge_timer_init_flag,
    CTLFLAG_RD | CTLFLAG_LOCKED, &bt_init_flag, 0, "");

static int sysctl_mach_bridge_timer_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t value = 0;
	int error = 0;
	/* User is querying buffer size */
	if (req->oldptr == USER_ADDR_NULL && req->newptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(value);
		return 0;
	}
	if (os_atomic_load(&bt_init_flag, acquire)) {
		if (req->newptr) {
			int new_value = 0;
			error = SYSCTL_IN(req, &new_value, sizeof(new_value));
			if (error) {
				return error;
			}
			if (new_value == 0 || new_value == 1) {
				value = mach_bridge_timer_enable(new_value, 1);
			} else {
				return EPERM;
			}
		} else {
			value = mach_bridge_timer_enable(0, 0);
		}
	}
	error = SYSCTL_OUT(req, &value, sizeof(value));
	return error;
}

SYSCTL_PROC(_machdep_remotetime, OID_AUTO, bridge_timer_enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mach_bridge_timer_enable, "I", "");

#endif /* CONFIG_MACH_BRIDGE_SEND_TIME */

static int sysctl_mach_bridge_remote_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t ltime = 0, rtime = 0;
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(rtime);
		return 0;
	}
	if (req->newptr) {
		int error = SYSCTL_IN(req, &ltime, sizeof(ltime));
		if (error) {
			return error;
		}
	}
	rtime = mach_bridge_remote_time(ltime);
	return SYSCTL_OUT(req, &rtime, sizeof(rtime));
}
SYSCTL_PROC(_machdep_remotetime, OID_AUTO, mach_bridge_remote_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mach_bridge_remote_time, "Q", "");

#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_MACH_BRIDGE_RECV_TIME
extern struct bt_params bt_params_get_latest(void);

static int sysctl_mach_bridge_conversion_params SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct bt_params params = {};
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(struct bt_params);
		return 0;
	}
	if (req->newptr) {
		return EPERM;
	}
	params = bt_params_get_latest();
	return SYSCTL_OUT(req, &params, MIN(sizeof(params), req->oldlen));
}

SYSCTL_PROC(_machdep_remotetime, OID_AUTO, conversion_params,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0,
    0, sysctl_mach_bridge_conversion_params, "S,bt_params", "");

#endif /* CONFIG_MACH_BRIDGE_RECV_TIME */

#if DEVELOPMENT || DEBUG
#if __AMP__
#include <pexpert/pexpert.h>
extern int32_t sysctl_get_bound_cpuid(void);
extern void sysctl_thread_bind_cpuid(int32_t cpuid);
static int
sysctl_kern_sched_thread_bind_cpu SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int32_t cpuid = sysctl_get_bound_cpuid();

	int32_t new_value;
	int changed;
	int error = sysctl_io_number(req, cpuid, sizeof cpuid, &new_value, &changed);
	if (error) {
		return error;
	}

	if (changed) {
		sysctl_thread_bind_cpuid(new_value);
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cpu, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cpu, "I", "");

extern char sysctl_get_bound_cluster_type(void);
extern void sysctl_thread_bind_cluster_type(char cluster_type);
static int
sysctl_kern_sched_thread_bind_cluster_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstb", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char cluster_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_thread_bind_cluster_type(cluster_type);
out:
	cluster_type = sysctl_get_bound_cluster_type();
	buff[0] = cluster_type;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_bind_cluster_type, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_thread_bind_cluster_type, "A", "");

extern char sysctl_get_task_cluster_type(void);
extern void sysctl_task_set_cluster_type(char cluster_type);
static int
sysctl_kern_sched_task_set_cluster_type SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	if (!PE_parse_boot_argn("enable_skstsct", NULL, 0)) {
		return ENOENT;
	}

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char cluster_type = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_task_set_cluster_type(cluster_type);
out:
	cluster_type = sysctl_get_task_cluster_type();
	buff[0] = cluster_type;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_cluster_type, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_sched_task_set_cluster_type, "A", "");

#if CONFIG_SCHED_EDGE

/*
 * Edge Scheduler Sysctls
 *
 * The Edge scheduler uses edge configurations to decide feasability of
 * migrating threads across clusters. The sysctls allow dynamic configuration
 * of the edge properties and edge weights. This configuration is typically
 * updated via callouts from CLPC.
 *
 * <Edge Multi-cluster Support Needed>
 */
extern sched_clutch_edge sched_edge_config_e_to_p;
extern sched_clutch_edge sched_edge_config_p_to_e;
extern kern_return_t sched_edge_sysctl_configure_e_to_p(uint64_t);
extern kern_return_t sched_edge_sysctl_configure_p_to_e(uint64_t);
extern sched_clutch_edge sched_edge_e_to_p(void);
extern sched_clutch_edge sched_edge_p_to_e(void);

static int sysctl_sched_edge_config_e_to_p SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	kern_return_t kr;
	int64_t edge_config = 0;

	error = SYSCTL_IN(req, &edge_config, sizeof(edge_config));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		edge_config = sched_edge_e_to_p().sce_edge_packed;
		return SYSCTL_OUT(req, &edge_config, sizeof(edge_config));
	}

	kr = sched_edge_sysctl_configure_e_to_p(edge_config);
	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, sched_edge_config_e_to_p, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_sched_edge_config_e_to_p, "Q", "Edge Scheduler Config for E-to-P cluster");

static int sysctl_sched_edge_config_p_to_e SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	kern_return_t kr;
	int64_t edge_config = 0;

	error = SYSCTL_IN(req, &edge_config, sizeof(edge_config));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		edge_config = sched_edge_p_to_e().sce_edge_packed;
		return SYSCTL_OUT(req, &edge_config, sizeof(edge_config));
	}

	kr = sched_edge_sysctl_configure_p_to_e(edge_config);
	return SYSCTL_OUT(req, &kr, sizeof(kr));
}
SYSCTL_PROC(_kern, OID_AUTO, sched_edge_config_p_to_e, CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_sched_edge_config_p_to_e, "Q", "Edge Scheduler Config for P-to-E cluster");

extern int sched_edge_restrict_ut;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_restrict_ut, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_restrict_ut, 0, "Edge Scheduler Restrict UT Threads");
extern int sched_edge_restrict_bg;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_restrict_bg, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_restrict_ut, 0, "Edge Scheduler Restrict BG Threads");
extern int sched_edge_migrate_ipi_immediate;
SYSCTL_INT(_kern, OID_AUTO, sched_edge_migrate_ipi_immediate, CTLFLAG_RW | CTLFLAG_LOCKED, &sched_edge_migrate_ipi_immediate, 0, "Edge Scheduler uses immediate IPIs for migration event based on execution latency");

#endif /* CONFIG_SCHED_EDGE */

#endif /* __AMP__ */
#endif /* DEVELOPMENT || DEBUG */

extern uint32_t task_exc_guard_default;

SYSCTL_INT(_kern, OID_AUTO, task_exc_guard_default,
    CTLFLAG_RD | CTLFLAG_LOCKED, &task_exc_guard_default, 0, "");


static int
sysctl_kern_tcsm_available SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t value = machine_csv(CPUVN_CI) ? 1 : 0;

	if (req->newptr) {
		return EINVAL;
	}

	return SYSCTL_OUT(req, &value, sizeof(value));
}
SYSCTL_PROC(_kern, OID_AUTO, tcsm_available,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_tcsm_available, "I", "");


static int
sysctl_kern_tcsm_enable SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t soflags = 0;
	uint32_t old_value = thread_get_no_smt() ? 1 : 0;

	int error = SYSCTL_IN(req, &soflags, sizeof(soflags));
	if (error) {
		return error;
	}

	if (soflags && machine_csv(CPUVN_CI)) {
		thread_set_no_smt(true);
		machine_tecs(current_thread());
	}

	return SYSCTL_OUT(req, &old_value, sizeof(old_value));
}
SYSCTL_PROC(_kern, OID_AUTO, tcsm_enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_tcsm_enable, "I", "");


#if DEVELOPMENT || DEBUG
extern void sysctl_task_set_no_smt(char no_smt);
extern char sysctl_task_get_no_smt(void);

static int
sysctl_kern_sched_task_set_no_smt SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char buff[4];

	int error = SYSCTL_IN(req, buff, 1);
	if (error) {
		return error;
	}
	char no_smt = buff[0];

	if (!req->newptr) {
		goto out;
	}

	sysctl_task_set_no_smt(no_smt);
out:
	no_smt = sysctl_task_get_no_smt();
	buff[0] = no_smt;

	return SYSCTL_OUT(req, buff, 1);
}

SYSCTL_PROC(_kern, OID_AUTO, sched_task_set_no_smt, CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_task_set_no_smt, "A", "");

static int
sysctl_kern_sched_thread_set_no_smt(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int old_value = thread_get_no_smt() ? 1 : 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (changed) {
		thread_set_no_smt(!!new_value);
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, sched_thread_set_no_smt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY,
    0, 0, sysctl_kern_sched_thread_set_no_smt, "I", "");

static int
sysctl_kern_debug_get_preoslog SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	static bool oneshot_executed = false;
	size_t preoslog_size = 0;
	const char *preoslog = NULL;

	// DumpPanic pases a non-zero write value when it needs oneshot behaviour
	if (req->newptr) {
		uint8_t oneshot = 0;
		int error = SYSCTL_IN(req, &oneshot, sizeof(oneshot));
		if (error) {
			return error;
		}

		if (oneshot) {
			if (!OSCompareAndSwap8(false, true, &oneshot_executed)) {
				return EPERM;
			}
		}
	}

	preoslog = sysctl_debug_get_preoslog(&preoslog_size);
	if (preoslog == NULL || preoslog_size == 0) {
		return 0;
	}

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = preoslog_size;
		return 0;
	}

	return SYSCTL_OUT(req, preoslog, preoslog_size);
}

SYSCTL_PROC(_kern, OID_AUTO, preoslog, CTLTYPE_OPAQUE | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_debug_get_preoslog, "-", "");

static int
sysctl_kern_task_set_filter_msg_flag SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int new_value, changed;
	int old_value = task_get_filter_msg_flag(current_task()) ? 1 : 0;
	int error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (changed) {
		task_set_filter_msg_flag(current_task(), !!new_value);
	}

	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, task_set_filter_msg_flag, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_kern_task_set_filter_msg_flag, "I", "");

#endif /* DEVELOPMENT || DEBUG */
