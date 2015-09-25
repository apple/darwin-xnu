/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/ledger.h>
#include <kern/task.h>
#include <kern/telemetry.h>

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
#include <kern/wait_queue.h>
#include <kern/kalloc.h>
#include <sys/vnode_internal.h>

/* XXX should be in a header file somewhere */
void evsofree(struct socket *);
void evpipefree(struct pipe *);
void postpipeevent(struct pipe *, int);
void postevent(struct socket *, struct sockbuf *, int);
extern kern_return_t IOBSDGetPlatformUUID(__darwin_uuid_t uuid, mach_timespec_t timeoutp);

int rd_uio(struct proc *p, int fdes, uio_t uio, user_ssize_t *retval);
int wr_uio(struct proc *p, struct fileproc *fp, uio_t uio, user_ssize_t *retval);

__private_extern__ int	dofileread(vfs_context_t ctx, struct fileproc *fp,
								   user_addr_t bufp, user_size_t nbyte, 
								   off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int	dofilewrite(vfs_context_t ctx, struct fileproc *fp,
									user_addr_t bufp, user_size_t nbyte, 
									off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int	preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_vnode);
__private_extern__ void	donefileread(struct proc *p, struct fileproc *fp_ret, int fd);


/* Conflict wait queue for when selects collide (opaque type) */
struct wait_queue select_conflict_queue;

/*
 * Init routine called from bsd_init.c
 */
void select_wait_queue_init(void);
void
select_wait_queue_init(void)
{
	wait_queue_init(&select_conflict_queue, SYNC_POLICY_FIFO);
}

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_ops->fo_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data

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
	return(read_nocancel(p, (struct read_nocancel_args *)uap, retval));
}

int
read_nocancel(struct proc *p, struct read_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	int fd = uap->fd;
	struct vfs_context context;

	if ( (error = preparefileread(p, &fp, fd, 0)) )
	        return (error);

	context = *(vfs_context_current());
	context.vc_ucred = fp->f_fglob->fg_cred;

	error = dofileread(&context, fp, uap->cbuf, uap->nbyte,
			   (off_t)-1, 0, retval);

	donefileread(p, fp, fd);

	return (error);
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
	return(pread_nocancel(p, (struct pread_nocancel_args *)uap, retval));
}

int
pread_nocancel(struct proc *p, struct pread_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp = NULL;	/* fp set by preparefileread() */
	int fd = uap->fd;
	int error;
	struct vfs_context context;

	if ( (error = preparefileread(p, &fp, fd, 1)) )
		goto out;

	context = *(vfs_context_current());
	context.vc_ucred = fp->f_fglob->fg_cred;

	error = dofileread(&context, fp, uap->buf, uap->nbyte,
			uap->offset, FOF_OFFSET, retval);
	
	donefileread(p, fp, fd);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pread) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);

out:
	return (error);
}

/*
 * Code common for read and pread
 */

void
donefileread(struct proc *p, struct fileproc *fp, int fd)
{
	proc_fdlock_spin(p);
	fp_drop(p, fd, fp, 1);
        proc_fdunlock(p);
}

/*
 * Returns:	0			Success
 *		EBADF
 *		ESPIPE
 *		ENXIO
 *	fp_lookup:EBADF
 *	fo_read:???
 */
int
preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pread)
{
	vnode_t vp;
	int 	error;
	struct fileproc *fp;

	AUDIT_ARG(fd, fd);

	proc_fdlock_spin(p);

	error = fp_lookup(p, fd, &fp, 1);

	if (error) {
	        proc_fdunlock(p);
		return (error);
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
		vp = (struct vnode *)fp->f_fglob->fg_data;

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
	return (0);

out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return (error);
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
	long error = 0;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (nbyte > INT_MAX)
		return (EINVAL);

	if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_READ, 
									  &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_READ, 
									  &uio_buf[0], sizeof(uio_buf));
	}
	uio_addiov(auio, bufp, nbyte);

	bytecnt = nbyte;

	if ((error = fo_read(fp, auio, flags, ctx))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
	bytecnt -= uio_resid(auio);

	*retval = bytecnt;

	return (error);
}

/*      
 * Scatter read system call.
 *
 * Returns:	0			Success
 *		EINVAL
 *		ENOMEM
 *	copyin:EFAULT
 *	rd_uio:???
 */
int
readv(struct proc *p, struct readv_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return(readv_nocancel(p, (struct readv_nocancel_args *)uap, retval));
}

int
readv_nocancel(struct proc *p, struct readv_nocancel_args *uap, user_ssize_t *retval)
{
	uio_t auio = NULL;
	int error;
	struct user_iovec *iovp;

	/* Verify range bedfore calling uio_create() */
	if (uap->iovcnt <= 0 || uap->iovcnt > UIO_MAXIOV)
		return (EINVAL);

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(uap->iovcnt, 0,
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
	error = copyin_user_iovec_array(uap->iovp,
		IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
		uap->iovcnt, iovp);
	if (error) {
		goto ExitThisRoutine;
	}
	
	/* finalize uio_t for use and do the IO 
	 */
	error = uio_calculateresid(auio);
	if (error) {
		goto ExitThisRoutine;
	}
	error = rd_uio(p, uap->fd, auio, retval);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return (error);
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
	return(write_nocancel(p, (struct write_nocancel_args *)uap, retval));

}

int
write_nocancel(struct proc *p, struct write_nocancel_args *uap, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;      
	int fd = uap->fd;
	bool wrote_some = false;

	AUDIT_ARG(fd, fd);

	error = fp_lookup(p,fd,&fp,0);
	if (error)
		return(error);
	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		proc_fdlock(p);
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
		proc_fdunlock(p);
	} else {
		struct vfs_context context = *(vfs_context_current());
		context.vc_ucred = fp->f_fglob->fg_cred;

		error = dofilewrite(&context, fp, uap->cbuf, uap->nbyte,
			(off_t)-1, 0, retval);

		wrote_some = *retval > 0;
	}
	if (wrote_some)
	        fp_drop_written(p, fd, fp);
	else
	        fp_drop(p, fd, fp, 0);
	return(error);  
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
	return(pwrite_nocancel(p, (struct pwrite_nocancel_args *)uap, retval));
}

int
pwrite_nocancel(struct proc *p, struct pwrite_nocancel_args *uap, user_ssize_t *retval)
{
        struct fileproc *fp;
        int error; 
	int fd = uap->fd;
	vnode_t vp  = (vnode_t)0;
	bool wrote_some = false;

	AUDIT_ARG(fd, fd);

	error = fp_lookup(p,fd,&fp,0);
	if (error)
		return(error);

	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		proc_fdlock(p);
		error = fp_guard_exception(p, fd, fp, kGUARD_EXC_WRITE);
		proc_fdunlock(p);
	} else {
		struct vfs_context context = *vfs_context_current();
		context.vc_ucred = fp->f_fglob->fg_cred;

		if (fp->f_type != DTYPE_VNODE) {
			error = ESPIPE;
			goto errout;
		}
		vp = (vnode_t)fp->f_fglob->fg_data;
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
			wrote_some = *retval > 0;
        }
errout:
	if (wrote_some)
	        fp_drop_written(p, fd, fp);
	else
	        fp_drop(p, fd, fp, 0);

	KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pwrite) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);
	
        return(error);
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
	long error = 0;
	user_ssize_t bytecnt;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (nbyte > INT_MAX) {
		*retval = 0;
		return (EINVAL);
	}

	if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_WRITE, 
									  &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_WRITE, 
									  &uio_buf[0], sizeof(uio_buf));
	}
	uio_addiov(auio, bufp, nbyte);

	bytecnt = nbyte; 
	if ((error = fo_write(fp, auio, flags, ctx))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET &&
		    (fp->f_fglob->fg_lflags & FG_NOSIGPIPE) == 0) {
			/* XXX Raise the signal on the thread? */
			psignal(vfs_context_proc(ctx), SIGPIPE);
		}
	}
	bytecnt -= uio_resid(auio);
	*retval = bytecnt;

	return (error); 
}
        
/*      
 * Gather write system call  
 */     
int
writev(struct proc *p, struct writev_args *uap, user_ssize_t *retval)
{
	__pthread_testcancel(1);
	return(writev_nocancel(p, (struct writev_nocancel_args *)uap, retval));
}

int
writev_nocancel(struct proc *p, struct writev_nocancel_args *uap, user_ssize_t *retval)
{
	uio_t auio = NULL;
	int error;
	struct fileproc *fp;
	struct user_iovec *iovp;
	bool wrote_some = false;

	AUDIT_ARG(fd, uap->fd);

	/* Verify range bedfore calling uio_create() */
	if (uap->iovcnt <= 0 || uap->iovcnt > UIO_MAXIOV)
		return (EINVAL);

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(uap->iovcnt, 0,
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
	error = copyin_user_iovec_array(uap->iovp,
		IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
		uap->iovcnt, iovp);
	if (error) {
		goto ExitThisRoutine;
	}
	
	/* finalize uio_t for use and do the IO 
	 */
	error = uio_calculateresid(auio);
	if (error) {
		goto ExitThisRoutine;
	}

	error = fp_lookup(p, uap->fd, &fp, 0);
	if (error)
		goto ExitThisRoutine;
	
	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else if (FP_ISGUARDED(fp, GUARD_WRITE)) {
		proc_fdlock(p);
		error = fp_guard_exception(p, uap->fd, fp, kGUARD_EXC_WRITE);
		proc_fdunlock(p);
	} else {
		error = wr_uio(p, fp, auio, retval);
		wrote_some = *retval > 0;
	}
	
	if (wrote_some)
	        fp_drop_written(p, uap->fd, fp);
	else
	        fp_drop(p, uap->fd, fp, 0);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return (error);
}


int
wr_uio(struct proc *p, struct fileproc *fp, uio_t uio, user_ssize_t *retval)
{
	int error;
	user_ssize_t count;
	struct vfs_context context = *vfs_context_current();

	count = uio_resid(uio);

	context.vc_ucred = fp->f_cred;
	error = fo_write(fp, uio, 0, &context);
	if (error) {
		if (uio_resid(uio) != count && (error == ERESTART ||
						error == EINTR || error == EWOULDBLOCK))
		        error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET &&
		    (fp->f_fglob->fg_lflags & FG_NOSIGPIPE) == 0)
		        psignal(p, SIGPIPE);
	}
	*retval = count - uio_resid(uio);

	return(error);
}


int
rd_uio(struct proc *p, int fdes, uio_t uio, user_ssize_t *retval)
{
	struct fileproc *fp;
	int error;
	user_ssize_t count;
	struct vfs_context context = *vfs_context_current();

	if ( (error = preparefileread(p, &fp, fdes, 0)) )
	        return (error);

	count = uio_resid(uio);

	context.vc_ucred = fp->f_cred;

	error = fo_read(fp, uio, 0, &context);

	if (error) {
	        if (uio_resid(uio) != count && (error == ERESTART ||
						error == EINTR || error == EWOULDBLOCK))
		        error = 0;
	}
	*retval = count - uio_resid(uio);

	donefileread(p, fp, fdes);

	return (error);
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
#define STK_PARAMS	128
	char stkbuf[STK_PARAMS];
	int fd = uap->fd;
	u_long com = uap->com;
	struct vfs_context context = *vfs_context_current();

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(addr, uap->data);

	is64bit = proc_is64bit(p);
#if CONFIG_AUDIT
	if (is64bit)
		AUDIT_ARG(value64, com);
	else
		AUDIT_ARG(cmd, CAST_DOWN_EXPLICIT(int, com));
#endif /* CONFIG_AUDIT */

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if (size > IOCPARM_MAX)
			return ENOTTY;
	if (size > sizeof (stkbuf)) {
		if ((memp = (caddr_t)kalloc(size)) == 0)
			return ENOMEM;
		datap = memp;
	} else
		datap = &stkbuf[0];
	if (com & IOC_IN) {
		if (size) {
			error = copyin(uap->data, datap, size);
			if (error)
				goto out_nofp;
		} else {
			/* XXX - IOC_IN and no size?  we should proably return an error here!! */
			if (is64bit) {
				*(user_addr_t *)datap = uap->data;
			}
			else {
				*(uint32_t *)datap = (uint32_t)uap->data;
			}
		}
	} else if ((com & IOC_OUT) && size)
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(datap, size);
	else if (com & IOC_VOID) {
		/* XXX - this is odd since IOC_VOID means no parameters */
		if (is64bit) {
			*(user_addr_t *)datap = uap->data;
		}
		else {
			*(uint32_t *)datap = (uint32_t)uap->data;
		}
	}

	proc_fdlock(p);
	error = fp_lookup(p,fd,&fp,1);
	if (error)  {
		proc_fdunlock(p);
		goto out_nofp;
	}

	AUDIT_ARG(file, p, fp);

	if ((fp->f_flag & (FREAD | FWRITE)) == 0) {
			error = EBADF;
			goto out;
	}

	context.vc_ucred = fp->f_fglob->fg_cred;

#if CONFIG_MACF
	error = mac_file_check_ioctl(context.vc_ucred, fp->f_fglob, com);
	if (error)
		goto out;
#endif

	switch (com) {
	case FIONCLEX:
		*fdflags(p, fd) &= ~UF_EXCLOSE;
		break;

	case FIOCLEX:
		*fdflags(p, fd) |= UF_EXCLOSE;
		break;

	case FIONBIO:
		if ( (tmp = *(int *)datap) )
			fp->f_flag |= FNONBLOCK;
		else
			fp->f_flag &= ~FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, &context);
		break;

	case FIOASYNC:
		if ( (tmp = *(int *)datap) )
			fp->f_flag |= FASYNC;
		else
			fp->f_flag &= ~FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, &context);
		break;

	case FIOSETOWN:
		tmp = *(int *)datap;
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			break;
		}
		if (fp->f_type == DTYPE_PIPE) {
		        error = fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, &context);
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
		error = fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, &context);
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
		if (error == 0 && (com & IOC_OUT) && size)
			error = copyout(datap, uap->data, (u_int)size);
		break;
	}
out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

out_nofp:
	if (memp)
		kfree(memp, size);
	return(error);
}

int	selwait, nselcoll;
#define SEL_FIRSTPASS 1
#define SEL_SECONDPASS 2
extern int selcontinue(int error);
extern int selprocess(int error, int sel_pass);
static int selscan(struct proc *p, struct _select * sel, struct _select_data * seldata,
			int nfd, int32_t *retval, int sel_pass, wait_queue_sub_t wqsub);
static int selcount(struct proc *p, u_int32_t *ibits, int nfd, int *count);
static int seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup, int fromselcount);
static int seldrop(struct proc *p, u_int32_t *ibits, int nfd);

/*
 * Select system call.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EAGAIN			Nonconformant error if allocation fails
 *	selprocess:???
 */
int
select(struct proc *p, struct select_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(select_nocancel(p, (struct select_nocancel_args *)uap, retval));
}

int
select_nocancel(struct proc *p, struct select_nocancel_args *uap, int32_t *retval)
{
	int error = 0;
	u_int ni, nw, size;
	thread_t th_act;
	struct uthread	*uth;
	struct _select *sel;
	struct _select_data *seldata;
	int needzerofill = 1;
	int count = 0;

	th_act = current_thread();
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_select;
	seldata = &uth->uu_kevent.ss_select_data;
	*retval = 0;

	seldata->args = uap;
	seldata->retval = retval;

	if (uap->nd < 0) {
		return (EINVAL);
	}

	/* select on thread of process that already called proc_exit() */
	if (p->p_fd == NULL) {
		return (EBADF);
	}

	if (uap->nd > p->p_fd->fd_nfiles)
		uap->nd = p->p_fd->fd_nfiles; /* forgiving; slightly wrong */

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
		if (sel->ibits != NULL)
			FREE(sel->ibits, M_TEMP);
		if (sel->obits != NULL) {
			FREE(sel->obits, M_TEMP);
			/* NULL out; subsequent ibits allocation may fail */
			sel->obits = NULL;
		}

		MALLOC(sel->ibits, u_int32_t *, nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if (sel->ibits == NULL)
			return (EAGAIN);
		MALLOC(sel->obits, u_int32_t *, nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if (sel->obits == NULL) {
			FREE(sel->ibits, M_TEMP);
			sel->ibits = NULL;
			return (EAGAIN);
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
#define	getbits(name, x) \
	do { \
		if (uap->name && (error = copyin(uap->name, \
			(caddr_t)&sel->ibits[(x) * nw], ni))) \
			goto continuation; \
	} while (0)

	getbits(in, 0);
	getbits(ou, 1);
	getbits(ex, 2);
#undef	getbits

	if (uap->tv) {
		struct timeval atv;
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval atv64;
			error = copyin(uap->tv, (caddr_t)&atv64, sizeof(atv64));
			/* Loses resolution - assume timeout < 68 years */
			atv.tv_sec = atv64.tv_sec;
			atv.tv_usec = atv64.tv_usec;
		} else {
			struct user32_timeval atv32;
			error = copyin(uap->tv, (caddr_t)&atv32, sizeof(atv32));
			atv.tv_sec = atv32.tv_sec;
			atv.tv_usec = atv32.tv_usec;
		}
		if (error)
			goto continuation;
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto continuation;
		}

		clock_absolutetime_interval_to_deadline(
										tvtoabstime(&atv), &seldata->abstime);
	}
	else
		seldata->abstime = 0;

	if ( (error = selcount(p, sel->ibits, uap->nd, &count)) ) {
			goto continuation;
	}

	seldata->count = count;
	size = SIZEOF_WAITQUEUE_SET + (count * SIZEOF_WAITQUEUE_LINK);
	if (uth->uu_allocsize) {
		if (uth->uu_wqset == 0)
			panic("select: wql memory smashed");
		/* needed for the select now */
		if (size > uth->uu_allocsize) {
			kfree(uth->uu_wqset,  uth->uu_allocsize);
			uth->uu_allocsize = size;
			uth->uu_wqset = (wait_queue_set_t)kalloc(size);
			if (uth->uu_wqset == (wait_queue_set_t)NULL)
				panic("failed to allocate memory for waitqueue\n");
		}
	} else {
		uth->uu_allocsize = size;
		uth->uu_wqset = (wait_queue_set_t)kalloc(uth->uu_allocsize);
		if (uth->uu_wqset == (wait_queue_set_t)NULL)
			panic("failed to allocate memory for waitqueue\n");
	}
	bzero(uth->uu_wqset, size);
	seldata->wql = (char *)uth->uu_wqset + SIZEOF_WAITQUEUE_SET;
	wait_queue_set_init(uth->uu_wqset, (SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST));

continuation:

	if (error) {
		/*
		 * We have already cleaned up any state we established,
		 * either locally or as a result of selcount().  We don't
		 * need to wait_subqueue_unlink_all(), since we haven't set
		 * anything at this point.
		 */
		return (error);
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
	struct uthread	*uth;
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
	seldata = &uth->uu_kevent.ss_select_data;
	uap = seldata->args;
	retval = seldata->retval;

	if ((error != 0) && (sel_pass == SEL_FIRSTPASS))
			unwind = 0;
	if (seldata->count == 0)
			unwind = 0;
retry:
	if (error != 0) {
		sel_pass = SEL_FIRSTPASS;	/* Reset for seldrop */
		goto done;
	}

	ncoll = nselcoll;
	OSBitOrAtomic(P_SELECT, &p->p_flag);
	/* skip scans if the select is just for timeouts */
	if (seldata->count) {
		/*
		 * Clear out any dangling refs from prior calls; technically
		 * there should not be any.
		 */
		if (sel_pass == SEL_FIRSTPASS)
			wait_queue_sub_clearrefs(uth->uu_wqset);

		error = selscan(p, sel, seldata, uap->nd, retval, sel_pass, (wait_queue_sub_t)uth->uu_wqset);
		if (error || *retval) {
			goto done;
		}
		if (prepost) {
			/* if the select of log, then we canwakeup and discover some one
		 	* else already read the data; go toselct again if time permits
		 	*/
		 	prepost = 0;
		 	doretry = 1;
		}
		if (somewakeup) {
		 	somewakeup = 0;
		 	doretry = 1;
		}
	}

	if (uap->tv) {
		uint64_t	now;

		clock_get_uptime(&now);
		if (now >= seldata->abstime)
			goto done;
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
	if (seldata->count &&(sel_pass == SEL_SECONDPASS))
		panic("selprocess: 2nd pass assertwaiting");

	/* Wait Queue Subordinate has waitqueue as first element */
	wait_result = wait_queue_assert_wait_with_leeway((wait_queue_t)uth->uu_wqset,
					     NULL, THREAD_ABORTSAFE,
					     TIMEOUT_URGENCY_USER_NORMAL, seldata->abstime, 0);
	if (wait_result != THREAD_AWAKENED) {
		/* there are no preposted events */
		error = tsleep1(NULL, PSOCK | PCATCH,
				"select", 0, selcontinue);
	} else  {
		prepost = 1;
		error = 0;
	}

	if (error == 0) {
		sel_pass = SEL_SECONDPASS;
		if (!prepost)
			somewakeup = 1;
		goto retry;
	}
done:
	if (unwind) {
		wait_subqueue_unlink_all(uth->uu_wqset);
		seldrop(p, sel->ibits, uap->nd);
	}
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* select is not restarted after signals... */
	if (error == ERESTART)
		error = EINTR;
	if (error == EWOULDBLOCK)
		error = 0;
	nw = howmany(uap->nd, NFDBITS);
	ni = nw * sizeof(fd_mask);

#define	putbits(name, x) \
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
	return(error);
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
 *		wqsub			The per thread wait queue set
 *
 * Returns:	0			Success
 *		EIO			Invalid p->p_fd field XXX Obsolete?
 *		EBADF			One of the files in the bit vector is
 *						invalid.
 */
static int
selscan(struct proc *p, struct _select *sel, struct _select_data * seldata, int nfd, int32_t *retval,
	int sel_pass, wait_queue_sub_t wqsub)
{
	struct filedesc *fdp = p->p_fd;
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	int n = 0;		/* count of bits */
	int nc = 0;		/* bit vector offset (nc'th bit) */
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *optr;
	u_int nw;
	u_int32_t *ibits, *obits;
	char * wql;
	char * wql_ptr;
	int count;
	struct vfs_context context = *vfs_context_current();

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*retval=0;
		return(EIO);
	}
	ibits = sel->ibits;
	obits = sel->obits;
	wql = seldata->wql;

	nw = howmany(nfd, NFDBITS);

	count = seldata->count;

	nc = 0;
	if (count) {
		proc_fdlock(p);
		for (msk = 0; msk < 3; msk++) {
			iptr = (u_int32_t *)&ibits[msk * nw];
			optr = (u_int32_t *)&obits[msk * nw];

			for (i = 0; i < nfd; i += NFDBITS) {
				bits = iptr[i/NFDBITS];

				while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
					bits &= ~(1 << j);

					if (fd < fdp->fd_nfiles)
						fp = fdp->fd_ofiles[fd];
					else
						fp = NULL;

					if (fp == NULL || (fdp->fd_ofileflags[fd] & UF_RESERVED)) {
						/*
						 * If we abort because of a bad
						 * fd, let the caller unwind...
						 */
						proc_fdunlock(p);
						return(EBADF);
					}
					if (sel_pass == SEL_SECONDPASS) {
						wql_ptr = (char *)0;
						if ((fp->f_flags & FP_INSELECT) && (fp->f_waddr == (void *)wqsub)) {
							fp->f_flags &= ~FP_INSELECT;
							fp->f_waddr = (void *)0;
						}
					} else {
					        wql_ptr = (wql + nc * SIZEOF_WAITQUEUE_LINK);
						if (fp->f_flags & FP_INSELECT) {
							/* someone is already in select on this fp */
							fp->f_flags |= FP_SELCONFLICT;
							wait_queue_link(&select_conflict_queue, (wait_queue_set_t)wqsub);
						} else {
							fp->f_flags |= FP_INSELECT;
							fp->f_waddr = (void *)wqsub;
						}
					}

					context.vc_ucred = fp->f_cred;

					/* The select; set the bit, if true */
					if (fp->f_ops && fp->f_type
						&& fo_select(fp, flag[msk], wql_ptr, &context)) {
						optr[fd/NFDBITS] |= (1 << (fd % NFDBITS));
						n++;
					}
					nc++;
				}
			}
		}
		proc_fdunlock(p);
	}
	*retval = n;
	return (0);
}

int poll_callback(struct kqueue *, struct kevent64_s *, void *);

struct poll_continue_args {
	user_addr_t pca_fds;
	u_int pca_nfds;
	u_int pca_rfds;
};

int
poll(struct proc *p, struct poll_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(poll_nocancel(p, (struct poll_nocancel_args *)uap, retval));
}


int
poll_nocancel(struct proc *p, struct poll_nocancel_args *uap, int32_t *retval)
{
	struct poll_continue_args *cont;
	struct pollfd *fds;
	struct kqueue *kq;
	struct timeval atv;
	int ncoll, error = 0;
	u_int nfds = uap->nfds;
	u_int rfds = 0;
	u_int i;
	size_t ni;

	/*
	 * This is kinda bogus.  We have fd limits, but that is not
	 * really related to the size of the pollfd array.  Make sure
	 * we let the process use at least FD_SETSIZE entries and at
	 * least enough for the current limits.  We want to be reasonably
	 * safe, but not overly restrictive.
	 */
	if (nfds > OPEN_MAX ||
	    (nfds > p->p_rlimit[RLIMIT_NOFILE].rlim_cur && (proc_suser(p) || nfds > FD_SETSIZE)))
		return (EINVAL);

	kq = kqueue_alloc(p);
	if (kq == NULL)
		return (EAGAIN);

	ni = nfds * sizeof(struct pollfd) + sizeof(struct poll_continue_args);
	MALLOC(cont, struct poll_continue_args *, ni, M_TEMP, M_WAITOK);
	if (NULL == cont) {
		error = EAGAIN;
		goto out;
	}
	
	fds = (struct pollfd *)&cont[1];
	error = copyin(uap->fds, fds, nfds * sizeof(struct pollfd));
	if (error)
		goto out;

	if (uap->timeout != -1) {
		struct timeval rtv;

		atv.tv_sec = uap->timeout / 1000;
		atv.tv_usec = (uap->timeout % 1000) * 1000;
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto out;
		}
		getmicrouptime(&rtv);
		timevaladd(&atv, &rtv);
	} else {
		atv.tv_sec = 0;
		atv.tv_usec = 0;
	}

	/* JMM - all this P_SELECT stuff is bogus */
	ncoll = nselcoll;
	OSBitOrAtomic(P_SELECT, &p->p_flag);
	for (i = 0; i < nfds; i++) {
		short events = fds[i].events;
		struct kevent64_s kev;
		int kerror = 0;

		/* per spec, ignore fd values below zero */
		if (fds[i].fd < 0) {
			fds[i].revents = 0;
			continue;
		}

		/* convert the poll event into a kqueue kevent */
		kev.ident = fds[i].fd;
		kev.flags = EV_ADD | EV_ONESHOT | EV_POLL;
		kev.udata = CAST_USER_ADDR_T(&fds[i]);
		kev.fflags = 0;
		kev.data = 0;
		kev.ext[0] = 0;
		kev.ext[1] = 0;

		/* Handle input events */
		if (events & ( POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND | POLLHUP )) {
			kev.filter = EVFILT_READ;
			if (events & ( POLLPRI | POLLRDBAND ))
				kev.flags |= EV_OOBAND;
			kerror = kevent_register(kq, &kev, p);
		}

		/* Handle output events */
		if (kerror == 0 &&
		    events & ( POLLOUT | POLLWRNORM | POLLWRBAND )) {
			kev.filter = EVFILT_WRITE;
			kerror = kevent_register(kq, &kev, p);
		}

		/* Handle BSD extension vnode events */
		if (kerror == 0 &&
		    events & ( POLLEXTEND | POLLATTRIB | POLLNLINK | POLLWRITE )) {
			kev.filter = EVFILT_VNODE;
			kev.fflags = 0;
			if (events & POLLEXTEND)
				kev.fflags |= NOTE_EXTEND;
			if (events & POLLATTRIB)
				kev.fflags |= NOTE_ATTRIB;
			if (events & POLLNLINK)
				kev.fflags |= NOTE_LINK;
			if (events & POLLWRITE)
				kev.fflags |= NOTE_WRITE;
			kerror = kevent_register(kq, &kev, p);
		}

		if (kerror != 0) {
			fds[i].revents = POLLNVAL;
			rfds++;
		} else
			fds[i].revents = 0;
	}

	/* Did we have any trouble registering? */
	if (rfds > 0)
		goto done;

	/* scan for, and possibly wait for, the kevents to trigger */
	cont->pca_fds = uap->fds;
	cont->pca_nfds = nfds;
	cont->pca_rfds = rfds;
	error = kqueue_scan(kq, poll_callback, NULL, cont, &atv, p);
	rfds = cont->pca_rfds;

 done:
	OSBitAndAtomic(~((uint32_t)P_SELECT), &p->p_flag);
	/* poll is not restarted after signals... */
	if (error == ERESTART)
		error = EINTR;
	if (error == EWOULDBLOCK)
		error = 0;
	if (error == 0) {
		error = copyout(fds, uap->fds, nfds * sizeof(struct pollfd));
		*retval = rfds;
	}

 out:
	if (NULL != cont)
		FREE(cont, M_TEMP);

	kqueue_dealloc(kq);
	return (error);
}

int
poll_callback(__unused struct kqueue *kq, struct kevent64_s *kevp, void *data)
{
	struct poll_continue_args *cont = (struct poll_continue_args *)data;
	struct pollfd *fds = CAST_DOWN(struct pollfd *, kevp->udata);
	short prev_revents = fds->revents;
	short mask = 0;

	/* convert the results back into revents */
	if (kevp->flags & EV_EOF)
		fds->revents |= POLLHUP;
	if (kevp->flags & EV_ERROR)
		fds->revents |= POLLERR;

	switch (kevp->filter) {
	case EVFILT_READ:
		if (fds->revents & POLLHUP)
			mask = (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND );
		else {
			if ((kevp->flags & EV_ERROR) == 0 && kevp->data != 0)
				mask = (POLLIN | POLLRDNORM );
			if (kevp->flags & EV_OOBAND)
				mask |= ( POLLPRI | POLLRDBAND );
		}
		fds->revents |= (fds->events & mask);
		break;

	case EVFILT_WRITE:
		if (!(fds->revents & POLLHUP))
			fds->revents |= (fds->events & ( POLLOUT | POLLWRNORM | POLLWRBAND ));
		break;

	case EVFILT_VNODE:
		if (kevp->fflags & NOTE_EXTEND)
			fds->revents |= (fds->events & POLLEXTEND);
		if (kevp->fflags & NOTE_ATTRIB)
			fds->revents |= (fds->events & POLLATTRIB);
		if (kevp->fflags & NOTE_LINK)
			fds->revents |= (fds->events & POLLNLINK);
		if (kevp->fflags & NOTE_WRITE)
			fds->revents |= (fds->events & POLLWRITE);
		break;
	}

	if (fds->revents != 0 && prev_revents == 0)
		cont->pca_rfds++;

	return 0;
}
	
int
seltrue(__unused dev_t dev, __unused int flag, __unused struct proc *p)
{

	return (1);
}

/*
 * selcount
 *
 * Count the number of bits set in the input bit vector, and establish an
 * outstanding fp->f_iocount for each of the descriptors which will be in
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
	int error=0; 
	int dropcount;
	int need_wakeup = 0;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*countp = 0;
		return(EIO);
	}
	nw = howmany(nfd, NFDBITS);

	proc_fdlock(p);
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i/NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1 << j);

				if (fd < fdp->fd_nfiles)
					fp = fdp->fd_ofiles[fd];
				else
					fp = NULL;

				if (fp == NULL ||
					(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
						*countp = 0;
						error = EBADF;
						goto bad;
				}
				fp->f_iocount++;
				n++;
			}
		}
	}
	proc_fdunlock(p);

	*countp = n;
	return (0);

bad:
	dropcount = 0;
	
	if (n== 0)
		goto out;
	/* Ignore error return; it's already EBADF */
	(void)seldrop_locked(p, ibits, nfd, n, &need_wakeup, 1);

out:
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fpdrainwait);
	}
	return(error);
}


/*
 * seldrop_locked
 *
 * Drop outstanding wait queue references set up during selscan(); drop the
 * outstanding per fileproc f_iocount() picked up during the selcount().
 *
 * Parameters:	p			Process performing the select
 *		ibits			Input pit bector of fd's
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
seldrop_locked(struct proc *p, u_int32_t *ibits, int nfd, int lim, int *need_wakeup, int fromselcount)
{
	struct filedesc *fdp = p->p_fd;
	int msk, i, j, fd;
	u_int32_t bits;
	struct fileproc *fp;
	u_int32_t *iptr;
	u_int nw;
	int error = 0;
	int dropcount = 0;
	uthread_t uth = get_bsdthread_info(current_thread());

	*need_wakeup = 0;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		return(EIO);
	}

	nw = howmany(nfd, NFDBITS);

	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i/NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1 << j);
				fp = fdp->fd_ofiles[fd];
				/*
				 * If we've already dropped as many as were
				 * counted/scanned, then we are done.  
				 */
				if ((fromselcount != 0) && (++dropcount > lim))
					goto done;

				if (fp == NULL) {
					/* skip (now) bad fds */
					error = EBADF;
					continue;
				}
				/*
				 * Only clear the flag if we set it.  We'll
				 * only find that we set it if we had made
				 * at least one [partial] pass through selscan().
				 */
				if ((fp->f_flags & FP_INSELECT) && (fp->f_waddr == (void *)uth->uu_wqset)) {
					fp->f_flags &= ~FP_INSELECT;
					fp->f_waddr = (void *)0;
				}

				fp->f_iocount--;
				if (fp->f_iocount < 0)
					panic("f_iocount overdecrement!");

				if (fp->f_iocount == 0) {
					/*
					 * The last iocount is responsible for clearing
					 * selconfict flag - even if we didn't set it -
					 * and is also responsible for waking up anyone
					 * waiting on iocounts to drain.
					 */
					if (fp->f_flags & FP_SELCONFLICT)
						fp->f_flags &= ~FP_SELCONFLICT;
					if (p->p_fpdrainwait) {
						p->p_fpdrainwait = 0;
						*need_wakeup = 1;
					}
				}
			}
		}
	}
done:
	return (error);
}


static int
seldrop(struct proc *p, u_int32_t *ibits, int nfd)
{
	int error;
	int need_wakeup = 0;

	proc_fdlock(p);
	error =  seldrop_locked(p, ibits, nfd, nfd, &need_wakeup, 0);
	proc_fdunlock(p);
	if (need_wakeup) {
		wakeup(&p->p_fpdrainwait);
	}
	return (error);
}

/*
 * Record a select request.
 */
void
selrecord(__unused struct proc *selector, struct selinfo *sip, void * p_wql)
{
	thread_t	cur_act = current_thread();
	struct uthread * ut = get_bsdthread_info(cur_act);

	/* need to look at collisions */

	/*do not record if this is second pass of select */
	if(p_wql == (void *)0) {
		return;
	}

	if ((sip->si_flags & SI_INITED) == 0) {
		wait_queue_init(&sip->si_wait_queue, SYNC_POLICY_FIFO);
		sip->si_flags |= SI_INITED;
		sip->si_flags &= ~SI_CLEAR;
	}

	if (sip->si_flags & SI_RECORDED) {
		sip->si_flags |= SI_COLL;
	} else
		sip->si_flags &= ~SI_COLL;

	sip->si_flags |= SI_RECORDED;
	if (!wait_queue_member(&sip->si_wait_queue, ut->uu_wqset))
		wait_queue_link_noalloc(&sip->si_wait_queue, ut->uu_wqset,
					(wait_queue_link_t)p_wql);

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
		wait_queue_wakeup_all(&sip->si_wait_queue, NULL, THREAD_AWAKENED);
		sip->si_flags &= ~SI_RECORDED;
	}

}

void 
selthreadclear(struct selinfo *sip)
{

	if ((sip->si_flags & SI_INITED) == 0) {
		return;
	}
	if (sip->si_flags & SI_RECORDED) {
			selwakeup(sip);
			sip->si_flags &= ~(SI_RECORDED | SI_COLL);
	}
	sip->si_flags |= SI_CLEAR;
	wait_queue_unlink_all(&sip->si_wait_queue);
}




#define DBG_POST	0x10
#define DBG_WATCH	0x11
#define DBG_WAIT	0x12
#define DBG_MOD		0x13
#define DBG_EWAKEUP	0x14
#define DBG_ENQUEUE	0x15
#define DBG_DEQUEUE	0x16

#define DBG_MISC_POST MISCDBG_CODE(DBG_EVENT,DBG_POST)
#define DBG_MISC_WATCH MISCDBG_CODE(DBG_EVENT,DBG_WATCH)
#define DBG_MISC_WAIT MISCDBG_CODE(DBG_EVENT,DBG_WAIT)
#define DBG_MISC_MOD MISCDBG_CODE(DBG_EVENT,DBG_MOD)
#define DBG_MISC_EWAKEUP MISCDBG_CODE(DBG_EVENT,DBG_EWAKEUP)
#define DBG_MISC_ENQUEUE MISCDBG_CODE(DBG_EVENT,DBG_ENQUEUE)
#define DBG_MISC_DEQUEUE MISCDBG_CODE(DBG_EVENT,DBG_DEQUEUE)


#define EVPROCDEQUE(p, evq)	do {				\
	proc_lock(p);						\
	if (evq->ee_flags & EV_QUEUED) {			\
	        TAILQ_REMOVE(&p->p_evlist, evq, ee_plist);	\
		evq->ee_flags &= ~EV_QUEUED;			\
	}							\
	proc_unlock(p);						\
} while (0);


/*
 * called upon socket close. deque and free all events for
 * the socket...  socket must be locked by caller.
 */
void
evsofree(struct socket *sp)
{
        struct eventqelt *evq, *next;
	proc_t 	p;

	if (sp == NULL)
	        return;

	for (evq = sp->so_evlist.tqh_first; evq != NULL; evq = next) {
	        next = evq->ee_slist.tqe_next;
		p = evq->ee_proc;

		if (evq->ee_flags & EV_QUEUED) {
		        EVPROCDEQUE(p, evq);
		}
		TAILQ_REMOVE(&sp->so_evlist, evq, ee_slist); // remove from socket q
		FREE(evq, M_TEMP);
	}
}


/*
 * called upon pipe close. deque and free all events for
 * the pipe... pipe must be locked by caller
 */
void
evpipefree(struct pipe *cpipe)
{
        struct eventqelt *evq, *next;
	proc_t 	p;

	for (evq = cpipe->pipe_evlist.tqh_first; evq != NULL; evq = next) {
	        next = evq->ee_slist.tqe_next;
		p = evq->ee_proc;

		EVPROCDEQUE(p, evq);

		TAILQ_REMOVE(&cpipe->pipe_evlist, evq, ee_slist); // remove from pipe q
		FREE(evq, M_TEMP);
	}
}


/*
 * enqueue this event if it's not already queued. wakeup
 * the proc if we do queue this event to it...
 * entered with proc lock held... we drop it before
 * doing the wakeup and return in that state
 */
static void
evprocenque(struct eventqelt *evq)
{
        proc_t	p;

	assert(evq);
	p = evq->ee_proc;

	KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_START, (uint32_t)evq, evq->ee_flags, evq->ee_eventmask,0,0);

	proc_lock(p);

	if (evq->ee_flags & EV_QUEUED) {
	        proc_unlock(p);

	        KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
		return;
	}
	evq->ee_flags |= EV_QUEUED;

	TAILQ_INSERT_TAIL(&p->p_evlist, evq, ee_plist);

	proc_unlock(p);

	wakeup(&p->p_evlist);

	KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
}


/*
 * pipe lock must be taken by the caller
 */
void
postpipeevent(struct pipe *pipep, int event)
{
	int	mask;
	struct eventqelt *evq;

	if (pipep == NULL)
	        return;
	KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_START, event,0,0,1,0);

	for (evq = pipep->pipe_evlist.tqh_first;
	     evq != NULL; evq = evq->ee_slist.tqe_next) {

	        if (evq->ee_eventmask == 0)
		        continue;
	        mask = 0;

		switch (event & (EV_RWBYTES | EV_RCLOSED | EV_WCLOSED)) {

		case EV_RWBYTES:
		  if ((evq->ee_eventmask & EV_RE) && pipep->pipe_buffer.cnt) {
		          mask |= EV_RE;
			  evq->ee_req.er_rcnt = pipep->pipe_buffer.cnt;
		  }
		  if ((evq->ee_eventmask & EV_WR) && 
		      (MAX(pipep->pipe_buffer.size,PIPE_SIZE) - pipep->pipe_buffer.cnt) >= PIPE_BUF) {

		          if (pipep->pipe_state & PIPE_EOF) {
			          mask |= EV_WR|EV_RESET;
				  break;
			  }
			  mask |= EV_WR;
			  evq->ee_req.er_wcnt = MAX(pipep->pipe_buffer.size, PIPE_SIZE) - pipep->pipe_buffer.cnt;
		  }
		  break;

		case EV_WCLOSED:
		case EV_RCLOSED:
		  if ((evq->ee_eventmask & EV_RE)) {
		          mask |= EV_RE|EV_RCLOSED;
		  }
		  if ((evq->ee_eventmask & EV_WR)) {
		          mask |= EV_WR|EV_WCLOSED;
		  }
		  break;

		default:
		  return;
		}
		if (mask) {
		        /*
			 * disarm... postevents are nops until this event is 'read' via
			 * waitevent and then re-armed via modwatch
			 */
		        evq->ee_eventmask = 0;

			/*
			 * since events are disarmed until after the waitevent
			 * the ee_req.er_xxxx fields can't change once we've
			 * inserted this event into the proc queue...
			 * therefore, the waitevent will see a 'consistent'
			 * snapshot of the event, even though it won't hold
			 * the pipe lock, and we're updating the event outside
			 * of the proc lock, which it will hold
			 */
		        evq->ee_req.er_eventbits |= mask;

			KERNEL_DEBUG(DBG_MISC_POST, (uint32_t)evq, evq->ee_req.er_eventbits, mask, 1,0);

			evprocenque(evq);
		}
	}
	KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_END, 0,0,0,1,0);
}

#if SOCKETS
/*
 * given either a sockbuf or a socket run down the
 * event list and queue ready events found...
 * the socket must be locked by the caller
 */
void
postevent(struct socket *sp, struct sockbuf *sb, int event)
{
        int	mask;
	struct	eventqelt *evq;
	struct	tcpcb *tp;

	if (sb)
	        sp = sb->sb_so;
	if (sp == NULL)
	        return;

	KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_START, (int)sp, event, 0, 0, 0);

	for (evq = sp->so_evlist.tqh_first;
	     evq != NULL; evq = evq->ee_slist.tqe_next) {

	        if (evq->ee_eventmask == 0)
		        continue;
	        mask = 0;

		/* ready for reading:
		   - byte cnt >= receive low water mark
		   - read-half of conn closed
		   - conn pending for listening sock
		   - socket error pending

		   ready for writing
		   - byte cnt avail >= send low water mark
		   - write half of conn closed
		   - socket error pending
		   - non-blocking conn completed successfully

		   exception pending
		   - out of band data
		   - sock at out of band mark
		*/

		switch (event & EV_DMASK) {

		case EV_OOB:
		  if ((evq->ee_eventmask & EV_EX)) {
		          if (sp->so_oobmark || ((sp->so_state & SS_RCVATMARK)))
			          mask |= EV_EX|EV_OOB;
		  }
		  break;

		case EV_RWBYTES|EV_OOB:
		  if ((evq->ee_eventmask & EV_EX)) {
		          if (sp->so_oobmark || ((sp->so_state & SS_RCVATMARK)))
			          mask |= EV_EX|EV_OOB;
		  }
		  /*
		   * fall into the next case
		   */
		case EV_RWBYTES:
		  if ((evq->ee_eventmask & EV_RE) && soreadable(sp)) {
			  /* for AFP/OT purposes; may go away in future */
		          if ((SOCK_DOM(sp) == PF_INET ||
			      SOCK_DOM(sp) == PF_INET6) &&
			      SOCK_PROTO(sp) == IPPROTO_TCP &&
			      (sp->so_error == ECONNREFUSED ||
			      sp->so_error == ECONNRESET)) {
			          if (sp->so_pcb == NULL ||
				      sotoinpcb(sp)->inp_state ==
				      INPCB_STATE_DEAD ||
				      (tp = sototcpcb(sp)) == NULL ||
				      tp->t_state == TCPS_CLOSED) {
				          mask |= EV_RE|EV_RESET;
					  break;
				  }
			  }
			  mask |= EV_RE;
			  evq->ee_req.er_rcnt = sp->so_rcv.sb_cc;

			  if (sp->so_state & SS_CANTRCVMORE) {
			          mask |= EV_FIN;
				  break;
			  }
		  }
		  if ((evq->ee_eventmask & EV_WR) && sowriteable(sp)) {
			  /* for AFP/OT purposes; may go away in future */
		          if ((SOCK_DOM(sp) == PF_INET ||
			      SOCK_DOM(sp) == PF_INET6) &&
			      SOCK_PROTO(sp) == IPPROTO_TCP &&
			      (sp->so_error == ECONNREFUSED ||
			      sp->so_error == ECONNRESET)) {
			          if (sp->so_pcb == NULL ||
				      sotoinpcb(sp)->inp_state ==
				      INPCB_STATE_DEAD ||
				      (tp = sototcpcb(sp)) == NULL ||
				      tp->t_state == TCPS_CLOSED) {
					  mask |= EV_WR|EV_RESET;
					  break;
				  }
			  }
			  mask |= EV_WR;
			  evq->ee_req.er_wcnt = sbspace(&sp->so_snd);
		  }
		  break;

		case EV_RCONN:
		  if ((evq->ee_eventmask & EV_RE)) {
			  mask |= EV_RE|EV_RCONN;
		          evq->ee_req.er_rcnt = sp->so_qlen + 1;  // incl this one
		  }
		  break;

		case EV_WCONN:
		  if ((evq->ee_eventmask & EV_WR)) {
		          mask |= EV_WR|EV_WCONN;
		  }
		  break;

		case EV_RCLOSED:
		  if ((evq->ee_eventmask & EV_RE)) {
		          mask |= EV_RE|EV_RCLOSED;
		  }
		  break;

		case EV_WCLOSED:
		  if ((evq->ee_eventmask & EV_WR)) {
		          mask |= EV_WR|EV_WCLOSED;
		  }
		  break;

		case EV_FIN:
		  if (evq->ee_eventmask & EV_RE) {
		          mask |= EV_RE|EV_FIN;
		  }
		  break;

		case EV_RESET:
		case EV_TIMEOUT:
		  if (evq->ee_eventmask & EV_RE) {
		          mask |= EV_RE | event;
		  } 
		  if (evq->ee_eventmask & EV_WR) {
		          mask |= EV_WR | event;
		  }
		  break;

		default:
		  KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_END, (int)sp, -1, 0, 0, 0);
		  return;
		} /* switch */

		KERNEL_DEBUG(DBG_MISC_POST, (int)evq, evq->ee_eventmask, evq->ee_req.er_eventbits, mask, 0);

		if (mask) {
		        /*
			 * disarm... postevents are nops until this event is 'read' via
			 * waitevent and then re-armed via modwatch
			 */
		        evq->ee_eventmask = 0;

			/*
			 * since events are disarmed until after the waitevent
			 * the ee_req.er_xxxx fields can't change once we've
			 * inserted this event into the proc queue...
			 * since waitevent can't see this event until we 
			 * enqueue it, waitevent will see a 'consistent'
			 * snapshot of the event, even though it won't hold
			 * the socket lock, and we're updating the event outside
			 * of the proc lock, which it will hold
			 */
		        evq->ee_req.er_eventbits |= mask;

			evprocenque(evq);
		}
	}
	KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_END, (int)sp, 0, 0, 0, 0);
}
#endif /* SOCKETS */


/*
 * watchevent system call. user passes us an event to watch
 * for. we malloc an event object, initialize it, and queue
 * it to the open socket. when the event occurs, postevent()
 * will enque it back to our proc where we can retrieve it
 * via waitevent().
 *
 * should this prevent duplicate events on same socket?
 *
 * Returns:
 *		ENOMEM			No memory for operation
 *	copyin:EFAULT
 */
int
watchevent(proc_t p, struct watchevent_args *uap, __unused int *retval)
{
	struct eventqelt *evq = (struct eventqelt *)0;
	struct eventqelt *np = NULL;
	struct eventreq64 *erp;
	struct fileproc *fp = NULL;
	int error;

	KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_START, 0,0,0,0,0);

	// get a qelt and fill with users req
	MALLOC(evq, struct eventqelt *, sizeof(struct eventqelt), M_TEMP, M_WAITOK);

	if (evq == NULL)
		return (ENOMEM);
	erp = &evq->ee_req;

	// get users request pkt

	if (IS_64BIT_PROCESS(p)) {
	        error = copyin(uap->u_req, (caddr_t)erp, sizeof(struct eventreq64));
	} else {
	        struct eventreq32 er32;

	        error = copyin(uap->u_req, (caddr_t)&er32, sizeof(struct eventreq32));
		if (error == 0) {
		       /*
			* the user only passes in the
			* er_type, er_handle and er_data...
			* the other fields are initialized
			* below, so don't bother to copy
			*/
		        erp->er_type = er32.er_type;
		        erp->er_handle = er32.er_handle;
		        erp->er_data = (user_addr_t)er32.er_data;
		}
	}
	if (error) {
	        FREE(evq, M_TEMP);
		KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, error,0,0,0,0);

		return(error);		
	}
	KERNEL_DEBUG(DBG_MISC_WATCH, erp->er_handle,uap->u_eventmask,(uint32_t)evq,0,0);

	// validate, freeing qelt if errors
	error = 0;
	proc_fdlock(p);

	if (erp->er_type != EV_FD) {
		error = EINVAL;
	} else if ((error = fp_lookup(p, erp->er_handle, &fp, 1)) != 0) {
		error = EBADF;
#if SOCKETS
	} else if (fp->f_type == DTYPE_SOCKET) {
		socket_lock((struct socket *)fp->f_data, 1);
		np = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
#endif /* SOCKETS */
	} else if (fp->f_type == DTYPE_PIPE) {
		PIPE_LOCK((struct pipe *)fp->f_data);
		np = ((struct pipe *)fp->f_data)->pipe_evlist.tqh_first;
	} else {
		fp_drop(p, erp->er_handle, fp, 1);
		error = EINVAL;
	}
	proc_fdunlock(p);

	if (error) {
		FREE(evq, M_TEMP);

		KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, error,0,0,0,0);
		return(error);
	}
		
	/*
	 * only allow one watch per file per proc
	 */
	for ( ; np != NULL; np = np->ee_slist.tqe_next) {
		if (np->ee_proc == p) {
#if SOCKETS
			if (fp->f_type == DTYPE_SOCKET)
				socket_unlock((struct socket *)fp->f_data, 1);
			else 
#endif /* SOCKETS */
				PIPE_UNLOCK((struct pipe *)fp->f_data);
			fp_drop(p, erp->er_handle, fp, 0);
			FREE(evq, M_TEMP);
			
			KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, EINVAL,0,0,0,0);
			return(EINVAL);
		}
	}
	erp->er_ecnt = erp->er_rcnt = erp->er_wcnt = erp->er_eventbits = 0;
	evq->ee_proc = p;
	evq->ee_eventmask = uap->u_eventmask & EV_MASK;
	evq->ee_flags = 0;

#if SOCKETS
	if (fp->f_type == DTYPE_SOCKET) {
		TAILQ_INSERT_TAIL(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
		postevent((struct socket *)fp->f_data, 0, EV_RWBYTES); // catch existing events

		socket_unlock((struct socket *)fp->f_data, 1);
	} else
#endif /* SOCKETS */
	{
		TAILQ_INSERT_TAIL(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist);
		postpipeevent((struct pipe *)fp->f_data, EV_RWBYTES);

		PIPE_UNLOCK((struct pipe *)fp->f_data);
	}
	fp_drop_event(p, erp->er_handle, fp);

	KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, 0,0,0,0,0);
	return(0);
}



/*
 * waitevent system call.
 * grabs the next waiting event for this proc and returns
 * it. if no events, user can request to sleep with timeout
 * or without or poll mode
 *    ((tv != NULL && interval == 0) || tv == -1)
 */
int
waitevent(proc_t p, struct waitevent_args *uap, int *retval)
{
        int error = 0;
	struct eventqelt *evq;
	struct eventreq64 *erp;
	uint64_t abstime, interval;
	boolean_t fast_poll = FALSE;
	union {
	        struct eventreq64 er64;
	        struct eventreq32 er32;
	} uer;

	interval = 0;

	if (uap->tv) {
		struct timeval atv;
		/*
		 * check for fast poll method
		 */
		if (IS_64BIT_PROCESS(p)) {
		        if (uap->tv == (user_addr_t)-1)
			        fast_poll = TRUE;
		} else if (uap->tv == (user_addr_t)((uint32_t)-1))
		        fast_poll = TRUE;

		if (fast_poll == TRUE) {
		        if (p->p_evlist.tqh_first == NULL) {
				KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_NONE, -1,0,0,0,0);
				/*
				 * poll failed
				 */
			        *retval = 1;
				return (0);
			}
			proc_lock(p);
			goto retry;
		}
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval atv64;
			error = copyin(uap->tv, (caddr_t)&atv64, sizeof(atv64));
			/* Loses resolution - assume timeout < 68 years */
			atv.tv_sec = atv64.tv_sec;
			atv.tv_usec = atv64.tv_usec;
		} else {
			struct user32_timeval atv32;
			error = copyin(uap->tv, (caddr_t)&atv32, sizeof(atv32));
			atv.tv_sec = atv32.tv_sec;
			atv.tv_usec = atv32.tv_usec;
		}

		if (error)
			return(error);
		if (itimerfix(&atv)) {
			error = EINVAL;
			return(error);
		}
		interval = tvtoabstime(&atv);
	}
	KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_START, 0,0,0,0,0);

	proc_lock(p);
retry:
	if ((evq = p->p_evlist.tqh_first) != NULL) {
	        /*
		 * found one... make a local copy while it's still on the queue
		 * to prevent it from changing while in the midst of copying
		 * don't want to hold the proc lock across a copyout because
		 * it might block on a page fault at the target in user space
		 */
	        erp = &evq->ee_req;

		if (IS_64BIT_PROCESS(p))
		        bcopy((caddr_t)erp, (caddr_t)&uer.er64, sizeof (struct eventreq64));
		else {
		        uer.er32.er_type  = erp->er_type;
		        uer.er32.er_handle  = erp->er_handle;
		        uer.er32.er_data  = (uint32_t)erp->er_data;
		        uer.er32.er_ecnt  = erp->er_ecnt;
		        uer.er32.er_rcnt  = erp->er_rcnt;
		        uer.er32.er_wcnt  = erp->er_wcnt;
		        uer.er32.er_eventbits = erp->er_eventbits;
		}
	        TAILQ_REMOVE(&p->p_evlist, evq, ee_plist);

		evq->ee_flags &= ~EV_QUEUED;

		proc_unlock(p);

		if (IS_64BIT_PROCESS(p))
		        error = copyout((caddr_t)&uer.er64, uap->u_req, sizeof(struct eventreq64));
		else
		        error = copyout((caddr_t)&uer.er32, uap->u_req, sizeof(struct eventreq32));

		KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, error,
			     evq->ee_req.er_handle,evq->ee_req.er_eventbits,(uint32_t)evq,0);
		return (error);
	}
	else {
		if (uap->tv && interval == 0) {
			proc_unlock(p);
			*retval = 1;  // poll failed

			KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, error,0,0,0,0);
			return (error);
		}
		if (interval != 0)
			clock_absolutetime_interval_to_deadline(interval, &abstime);
		else
		        abstime = 0;

		KERNEL_DEBUG(DBG_MISC_WAIT, 1,(uint32_t)&p->p_evlist,0,0,0);

		error = msleep1(&p->p_evlist, &p->p_mlock, (PSOCK | PCATCH), "waitevent", abstime);

		KERNEL_DEBUG(DBG_MISC_WAIT, 2,(uint32_t)&p->p_evlist,0,0,0);

		if (error == 0)
			goto retry;
		if (error == ERESTART)
			error = EINTR;
		if (error == EWOULDBLOCK) {
			*retval = 1;
			error = 0;
		}
	}
	proc_unlock(p);

	KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, 0,0,0,0,0);
	return (error);
}


/*
 * modwatch system call. user passes in event to modify.
 * if we find it we reset the event bits and que/deque event
 * it needed.
 */
int
modwatch(proc_t p, struct modwatch_args *uap, __unused int *retval)
{
	struct eventreq64 er;
	struct eventreq64 *erp = &er;
	struct eventqelt *evq = NULL;	/* protected by error return */
	int error;
	struct fileproc *fp;
	int flag;

	KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_START, 0,0,0,0,0);

	/*
	 * get user's request pkt
	 * just need the er_type and er_handle which sit above the
	 * problematic er_data (32/64 issue)... so only copy in
	 * those 2 fields
	 */
	if ((error = copyin(uap->u_req, (caddr_t)erp, sizeof(er.er_type) + sizeof(er.er_handle)))) {
	        KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, error,0,0,0,0);
	        return(error);
	}
	proc_fdlock(p);

	if (erp->er_type != EV_FD) {
		error = EINVAL;
	} else if ((error = fp_lookup(p, erp->er_handle, &fp, 1)) != 0) {
		error = EBADF;
#if SOCKETS
	} else if (fp->f_type == DTYPE_SOCKET) {
		socket_lock((struct socket *)fp->f_data, 1);
		evq = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
#endif /* SOCKETS */
	} else if (fp->f_type == DTYPE_PIPE) {
		PIPE_LOCK((struct pipe *)fp->f_data);
		evq = ((struct pipe *)fp->f_data)->pipe_evlist.tqh_first;
	} else {
		fp_drop(p, erp->er_handle, fp, 1);
		error = EINVAL;
	}

	if (error) {
		proc_fdunlock(p);
		KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, error,0,0,0,0);
		return(error);
	}

	if ((uap->u_eventmask == EV_RM) && (fp->f_flags & FP_WAITEVENT)) {
		fp->f_flags &= ~FP_WAITEVENT;
	}
	proc_fdunlock(p);

	// locate event if possible
	for ( ; evq != NULL; evq = evq->ee_slist.tqe_next) {
	        if (evq->ee_proc == p)
		        break;
	}
	if (evq == NULL) {
#if SOCKETS
		if (fp->f_type == DTYPE_SOCKET) 
			socket_unlock((struct socket *)fp->f_data, 1);
		else
#endif /* SOCKETS */
			PIPE_UNLOCK((struct pipe *)fp->f_data);
		fp_drop(p, erp->er_handle, fp, 0);
		KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, EINVAL,0,0,0,0);
		return(EINVAL);
	}
	KERNEL_DEBUG(DBG_MISC_MOD, erp->er_handle,uap->u_eventmask,(uint32_t)evq,0,0);

	if (uap->u_eventmask == EV_RM) {
		EVPROCDEQUE(p, evq);

#if SOCKETS
		if (fp->f_type == DTYPE_SOCKET) {
			TAILQ_REMOVE(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
			socket_unlock((struct socket *)fp->f_data, 1);
		} else
#endif /* SOCKETS */
		{
			TAILQ_REMOVE(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist);
			PIPE_UNLOCK((struct pipe *)fp->f_data);
		}
		fp_drop(p, erp->er_handle, fp, 0);
		FREE(evq, M_TEMP);
		KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, 0,0,0,0,0);
		return(0);
	}
	switch (uap->u_eventmask & EV_MASK) {
 
	case 0:
		flag = 0;
		break;

	case EV_RE:
	case EV_WR:
	case EV_RE|EV_WR:
		flag = EV_RWBYTES;
		break;

	case EV_EX:
		flag = EV_OOB;
		break;

	case EV_EX|EV_RE:
	case EV_EX|EV_WR:
	case EV_EX|EV_RE|EV_WR:
		flag = EV_OOB|EV_RWBYTES;
		break;

	default:
#if SOCKETS
		if (fp->f_type == DTYPE_SOCKET) 
			socket_unlock((struct socket *)fp->f_data, 1);
		else 
#endif /* SOCKETS */
			PIPE_UNLOCK((struct pipe *)fp->f_data);
		fp_drop(p, erp->er_handle, fp, 0);
		KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, EINVAL,0,0,0,0);
		return(EINVAL);
	}
	/*
	 * since we're holding the socket/pipe lock, the event
	 * cannot go from the unqueued state to the queued state
	 * however, it can go from the queued state to the unqueued state
	 * since that direction is protected by the proc_lock...
	 * so do a quick check for EV_QUEUED w/o holding the proc lock
	 * since by far the common case will be NOT EV_QUEUED, this saves
	 * us taking the proc_lock the majority of the time
	 */
	if (evq->ee_flags & EV_QUEUED) {
		/*
		 * EVPROCDEQUE will recheck the state after it grabs the proc_lock
		 */
		EVPROCDEQUE(p, evq);
	}
	/*
	 * while the event is off the proc queue and
	 * we're holding the socket/pipe lock
	 * it's safe to update these fields...
	 */
	evq->ee_req.er_eventbits = 0;
	evq->ee_eventmask = uap->u_eventmask & EV_MASK;

#if SOCKETS
	if (fp->f_type == DTYPE_SOCKET) {
		postevent((struct socket *)fp->f_data, 0, flag);
		socket_unlock((struct socket *)fp->f_data, 1);
	} else
#endif /* SOCKETS */
	{
		postpipeevent((struct pipe *)fp->f_data, flag);
		PIPE_UNLOCK((struct pipe *)fp->f_data);
	}
	fp_drop(p, erp->er_handle, fp, 0);
	KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, evq->ee_req.er_handle,evq->ee_eventmask,(uint32_t)fp->f_data,flag,0);
	return(0);
}

/* this routine is called from the close of fd with proc_fdlock held */
int
waitevent_close(struct proc *p, struct fileproc *fp)
{
	struct eventqelt *evq;


	fp->f_flags &= ~FP_WAITEVENT;

#if SOCKETS
	if (fp->f_type == DTYPE_SOCKET) {
	        socket_lock((struct socket *)fp->f_data, 1);
		evq = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
	} else
#endif /* SOCKETS */
	if (fp->f_type == DTYPE_PIPE) {
	        PIPE_LOCK((struct pipe *)fp->f_data);
		evq = ((struct pipe *)fp->f_data)->pipe_evlist.tqh_first;
	}
	else {
		return(EINVAL);
	}
	proc_fdunlock(p);


	// locate event if possible
	for ( ; evq != NULL; evq = evq->ee_slist.tqe_next) {
	        if (evq->ee_proc == p)
		        break;
	}
	if (evq == NULL) {
#if SOCKETS
	        if (fp->f_type == DTYPE_SOCKET) 
		        socket_unlock((struct socket *)fp->f_data, 1);
		else 
#endif /* SOCKETS */
		        PIPE_UNLOCK((struct pipe *)fp->f_data);

		proc_fdlock(p);

		return(EINVAL);
	}
	EVPROCDEQUE(p, evq);

#if SOCKETS
	if (fp->f_type == DTYPE_SOCKET) {
		TAILQ_REMOVE(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
		socket_unlock((struct socket *)fp->f_data, 1);
	} else
#endif /* SOCKETS */
	{
		TAILQ_REMOVE(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist);
		PIPE_UNLOCK((struct pipe *)fp->f_data);
	}
	FREE(evq, M_TEMP);

	proc_fdlock(p);

	return(0);
}


/*
 * gethostuuid
 *
 * Description:	Get the host UUID from IOKit and return it to user space.
 *
 * Parameters:	uuid_buf		Pointer to buffer to receive UUID
 *		timeout			Timespec for timout
 *		spi				SPI, skip sandbox check (temporary)
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
	mach_timespec_t mach_ts;	/* for IOKit call */
	__darwin_uuid_t uuid_kern;	/* for IOKit call */

	if (!uap->spi) {
	}

	/* Convert the 32/64 bit timespec into a mach_timespec_t */
	if ( proc_is64bit(p) ) {
		struct user64_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts));
		if (error)
			return (error);
		mach_ts.tv_sec = ts.tv_sec;
		mach_ts.tv_nsec = ts.tv_nsec;
	} else {
		struct user32_timespec ts;
		error = copyin(uap->timeoutp, &ts, sizeof(ts) );
		if (error)
			return (error);
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

	return (error);
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
	if (args->cmd == LEDGER_ENTRY_INFO)
		error = copyin(args->arg3, (char *)&len, sizeof (len));
	else if (args->cmd == LEDGER_TEMPLATE_INFO)
		error = copyin(args->arg2, (char *)&len, sizeof (len));
#ifdef LEDGER_DEBUG
	else if (args->cmd == LEDGER_LIMIT)
		error = copyin(args->arg2, (char *)&lla, sizeof (lla));
#endif
	if (error)
		return (error);
	if (len < 0)
		return (EINVAL);

	rval = 0;
	if (args->cmd != LEDGER_TEMPLATE_INFO) {
		pid = args->arg1;
		proc = proc_find(pid);
		if (proc == NULL)
			return (ESRCH);

#if CONFIG_MACF
		error = mac_proc_check_ledger(p, proc, args->cmd);
		if (error) {
			proc_rele(proc);
			return (error);
		}
#endif

		task = proc->task;
	}
		
	switch (args->cmd) {
#ifdef LEDGER_DEBUG
		case LEDGER_LIMIT: {
			if (!kauth_cred_issuser(kauth_cred_get()))
				rval = EPERM;
			rval = ledger_limit(task, &lla);
			proc_rele(proc);
			break;
		}
#endif
		case LEDGER_INFO: {
			struct ledger_info info;

			rval = ledger_info(task, &info);
			proc_rele(proc);
			if (rval == 0)
				rval = copyout(&info, args->arg2,
				    sizeof (info));
			break;
		}

		case LEDGER_ENTRY_INFO: {
			void *buf;
			int sz;

			rval = ledger_get_task_entry_info_multiple(task, &buf, &len);
			proc_rele(proc);
			if ((rval == 0) && (len > 0)) {
				sz = len * sizeof (struct ledger_entry_info);
				rval = copyout(buf, args->arg2, sz);
				kfree(buf, sz);
			}
			if (rval == 0)
				rval = copyout(&len, args->arg3, sizeof (len));
			break;
		}

		case LEDGER_TEMPLATE_INFO: {
			void *buf;
			int sz;

			rval = ledger_template_info(&buf, &len);
			if ((rval == 0) && (len > 0)) {
				sz = len * sizeof (struct ledger_template_info);
				rval = copyout(buf, args->arg1, sz);
				kfree(buf, sz);
			}
			if (rval == 0)
				rval = copyout(&len, args->arg2, sizeof (len));
			break;
		}

		default:
			rval = EINVAL;
	}

	return (rval);
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
#endif /* CONFIG_TELEMETRY */
	case TELEMETRY_CMD_VOUCHER_NAME:
		if (thread_set_voucher_name((mach_port_name_t)args->deadline))
			error = EINVAL;
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
