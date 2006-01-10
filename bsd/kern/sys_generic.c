/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/ioctl.h>
#include <sys/file_internal.h>
#include <sys/proc_internal.h>
#include <sys/socketvar.h>
#if KTRACE
#include <sys/uio_internal.h>
#else
#include <sys/uio.h>
#endif
#include <sys/kernel.h>
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

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/clock.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/pipe.h>

#include <bsm/audit_kernel.h>

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
#if KTRACE 
#include <sys/ktrace.h>
#endif
#include <sys/vnode_internal.h>

int rd_uio(struct proc *p, int fdes, uio_t uio, user_ssize_t *retval);
int wr_uio(struct proc *p, int fdes, uio_t uio, user_ssize_t *retval);
extern void	*get_bsduthreadarg(thread_t);
extern int	*get_bsduthreadrval(thread_t);

__private_extern__ int	dofileread(struct proc *p, struct fileproc *fp, int fd, 
								   user_addr_t bufp, user_size_t nbyte, 
								   off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int	dofilewrite(struct proc *p, struct fileproc *fp, int fd, 
									user_addr_t bufp, user_size_t nbyte, 
									off_t offset, int flags, user_ssize_t *retval);
__private_extern__ int	preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_vnode);
__private_extern__ void	donefileread(struct proc *p, struct fileproc *fp_ret, int fd);

#if NETAT
extern int appletalk_inited;
#endif /* NETAT */

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
/*
 * Read system call.
 */
int
read(p, uap, retval)
	struct proc *p;
	register struct read_args *uap;
	user_ssize_t *retval;
{
	struct fileproc *fp;
	int error;
	int fd = uap->fd;

	if ( (error = preparefileread(p, &fp, fd, 0)) )
	        return (error);

	error = dofileread(p, fp, uap->fd, uap->cbuf, uap->nbyte,
			   (off_t)-1, 0, retval);

	donefileread(p, fp, fd);

	return (error);
}

/* 
 * Pread system call
 */
int
pread(p, uap, retval)
	struct proc *p;
	register struct pread_args *uap;
	user_ssize_t *retval;
{
	struct fileproc *fp;
	int fd = uap->fd;
	int error;

	if ( (error = preparefileread(p, &fp, fd, 1)) )
	        return (error);

	error = dofileread(p, fp, uap->fd, uap->buf, uap->nbyte,
			uap->offset, FOF_OFFSET, retval);
	
	donefileread(p, fp, fd);

	if (!error)
	    KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pread) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);
	
	return (error);
}

/*
 * Code common for read and pread
 */

void
donefileread(struct proc *p, struct fileproc *fp, int fd)
{
	proc_fdlock(p);

	fp->f_flags &= ~FP_INCHRREAD;

	fp_drop(p, fd, fp, 1);
        proc_fdunlock(p);
}

int
preparefileread(struct proc *p, struct fileproc **fp_ret, int fd, int check_for_pread)
{
	vnode_t vp;
	int 	error;
	struct fileproc *fp;

	proc_fdlock(p);

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

		if (vp->v_type == VCHR)
			fp->f_flags |= FP_INCHRREAD;
	}

	*fp_ret = fp;

        proc_fdunlock(p);
	return (0);

out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return (error);
}


__private_extern__ int
dofileread(p, fp, fd, bufp, nbyte, offset, flags, retval)
	struct proc *p;
	struct fileproc *fp;
	int fd, flags;
	user_addr_t bufp;
	user_size_t nbyte;
	off_t offset;
	user_ssize_t *retval;
{
	uio_t auio;
	user_ssize_t bytecnt;
	long error = 0;
	char uio_buf[ UIO_SIZEOF(1) ];
#if KTRACE
	uio_t ktruio = NULL;
	char ktr_uio_buf[ UIO_SIZEOF(1) ];
	int didktr = 0;
#endif

	// LP64todo - do we want to raise this?
	if (nbyte > INT_MAX)
		return (EINVAL);

	if (IS_64BIT_PROCESS(p)) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_READ, 
									  &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_READ, 
									  &uio_buf[0], sizeof(uio_buf));
	}
	uio_addiov(auio, bufp, nbyte);

#if KTRACE
	/*
	* if tracing, save a copy of iovec
	*/
	if (KTRPOINT(p, KTR_GENIO)) {
		didktr = 1;

		if (IS_64BIT_PROCESS(p)) {
			ktruio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_READ, 
									  &ktr_uio_buf[0], sizeof(ktr_uio_buf));
		} else {
			ktruio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_READ, 
									  &ktr_uio_buf[0], sizeof(ktr_uio_buf));
		}
		uio_addiov(ktruio, bufp, nbyte);
	}
#endif
	bytecnt = nbyte;

	if ((error = fo_read(fp, auio, fp->f_cred, flags, p))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
	bytecnt -= uio_resid(auio);
#if KTRACE
	if (didktr && error == 0) {
		uio_setresid(ktruio, bytecnt);
		ktrgenio(p->p_tracep, fd, UIO_READ, ktruio, error);
	}
#endif  

	*retval = bytecnt;

	return (error);
}

/*      
 * Scatter read system call.
 */
int
readv(p, uap, retval)
	struct proc *p;
	register struct readv_args *uap;
	user_ssize_t *retval;
{
	uio_t auio = NULL;
	int error;
	int size_of_iovec;
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
	size_of_iovec = (IS_64BIT_PROCESS(p) ? sizeof(struct user_iovec) : sizeof(struct iovec));
	error = copyin(uap->iovp, (caddr_t)iovp, (uap->iovcnt * size_of_iovec));
	if (error) {
		goto ExitThisRoutine;
	}
	
	/* finalize uio_t for use and do the IO 
	 */
	uio_calculateresid(auio);
	error = rd_uio(p, uap->fd, auio, retval);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return (error);
}

/*
 * Write system call
 */
int
write(p, uap, retval)
	struct proc *p;
	register struct write_args *uap;
	user_ssize_t *retval;	
{
	struct fileproc *fp;
	int error;      
	int fd = uap->fd;

	error = fp_lookup(p,fd,&fp,0);
	if (error)
		return(error);
	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else {
		error = dofilewrite(p, fp, uap->fd, uap->cbuf, uap->nbyte,
			(off_t)-1, 0, retval);
	}
	if (error == 0)
	        fp_drop_written(p, fd, fp);
	else
	        fp_drop(p, fd, fp, 0);
	return(error);  
}

/*                          
 * pwrite system call
 */
int
pwrite(p, uap, retval)
	struct proc *p;
	register struct pwrite_args *uap;
	user_ssize_t *retval;	
{
        struct fileproc *fp;
        int error; 
	int fd = uap->fd;

	error = fp_lookup(p,fd,&fp,0);
	if (error)
		return(error);

	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
	} else {
		if (fp->f_type != DTYPE_VNODE) {
			error = ESPIPE;
		} else {
		    error = dofilewrite(p, fp, uap->fd, uap->buf, uap->nbyte,
			uap->offset, FOF_OFFSET, retval);
		}
        }
	if (error == 0)
	        fp_drop_written(p, fd, fp);
	else
	        fp_drop(p, fd, fp, 0);

	if (!error)
	    KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pwrite) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);
	
        return(error);
}

__private_extern__ int                  
dofilewrite(p, fp, fd, bufp, nbyte, offset, flags, retval)
	struct proc *p;
	struct fileproc *fp; 
	int fd, flags;
	user_addr_t bufp;
	user_size_t nbyte;   
	off_t offset; 
	user_ssize_t *retval;
{       
	uio_t auio;
	long error = 0;
	user_ssize_t bytecnt;
	char uio_buf[ UIO_SIZEOF(1) ];
#if KTRACE
	uio_t ktruio;
	int didktr = 0; 
	char ktr_uio_buf[ UIO_SIZEOF(1) ];
#endif

	// LP64todo - do we want to raise this?
	if (nbyte > INT_MAX)   
		return (EINVAL);

	if (IS_64BIT_PROCESS(p)) {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_WRITE, 
									  &uio_buf[0], sizeof(uio_buf));
	} else {
		auio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_WRITE, 
									  &uio_buf[0], sizeof(uio_buf));
	}
	uio_addiov(auio, bufp, nbyte);

#if KTRACE
	/*
	* if tracing, save a copy of iovec and uio
	*/
	if (KTRPOINT(p, KTR_GENIO)) {
		didktr = 1;

		if (IS_64BIT_PROCESS(p)) {
			ktruio = uio_createwithbuffer(1, offset, UIO_USERSPACE64, UIO_WRITE, 
										  &ktr_uio_buf[0], sizeof(ktr_uio_buf));
		} else {
			ktruio = uio_createwithbuffer(1, offset, UIO_USERSPACE32, UIO_WRITE, 
										  &ktr_uio_buf[0], sizeof(ktr_uio_buf));
		}
		uio_addiov(ktruio, bufp, nbyte);
	}
#endif  
	bytecnt = nbyte; 
	if ((error = fo_write(fp, auio, fp->f_cred, flags, p))) {
		if (uio_resid(auio) != bytecnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET)
			psignal(p, SIGPIPE);
	}
	bytecnt -= uio_resid(auio);
#if KTRACE 
	if (didktr && error == 0) {
		uio_setresid(ktruio, bytecnt);
		ktrgenio(p->p_tracep, fd, UIO_WRITE, ktruio, error);
	}
#endif  
	*retval = bytecnt;

	return (error); 
}
        
/*      
 * Gather write system call  
 */     
int
writev(p, uap, retval)
	struct proc *p;
	register struct writev_args *uap;
	user_ssize_t *retval;
{
	uio_t auio = NULL;
	int error;
	int size_of_iovec;
	struct user_iovec *iovp;

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
	size_of_iovec = (IS_64BIT_PROCESS(p) ? sizeof(struct user_iovec) : sizeof(struct iovec));
	error = copyin(uap->iovp, (caddr_t)iovp, (uap->iovcnt * size_of_iovec));
	if (error) {
		goto ExitThisRoutine;
	}
	
	/* finalize uio_t for use and do the IO 
	 */
	uio_calculateresid(auio);
	error = wr_uio(p, uap->fd, auio, retval);

ExitThisRoutine:
	if (auio != NULL) {
		uio_free(auio);
	}
	return (error);
}


int
wr_uio(p, fdes, uio, retval)
	struct proc *p;
	int fdes;
	register uio_t uio;
	user_ssize_t *retval;
{
	struct fileproc *fp;
	int error;
	user_ssize_t count;
#if KTRACE
	struct iovec_64 *ktriov = NULL;
	struct uio ktruio;
	int didktr = 0;
	u_int iovlen;
#endif

	error = fp_lookup(p,fdes,&fp,0);
	if (error)
		return(error);

	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	count = uio_resid(uio);
#if KTRACE
	/*
	 * if tracing, save a copy of iovec
	 */
	if (KTRPOINT(p, KTR_GENIO)) {
		iovlen = uio->uio_iovcnt *
			(IS_64BIT_PROCESS(p) ? sizeof (struct iovec_64) : sizeof (struct iovec_32));
		MALLOC(ktriov, struct iovec_64 *, iovlen, M_TEMP, M_WAITOK);
		if (ktriov != NULL) {
			bcopy((caddr_t)uio->uio_iovs.iov64p, (caddr_t)ktriov, iovlen);
			ktruio = *uio;
			didktr = 1;
		}
	} 
#endif  
	error = fo_write(fp, uio, fp->f_cred, 0, p);
	if (error) {
		if (uio_resid(uio) != count && (error == ERESTART ||
						error == EINTR || error == EWOULDBLOCK))
		        error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET)
		        psignal(p, SIGPIPE);
	}
	*retval = count - uio_resid(uio);

#if KTRACE
	if (didktr) {
		if (error == 0) {
			ktruio.uio_iovs.iov64p = ktriov; 
			uio_setresid(&ktruio, *retval);
			ktrgenio(p->p_tracep, fdes, UIO_WRITE, &ktruio, error);
		}
		FREE(ktriov, M_TEMP);
	}
#endif

out:
	if ( (error == 0) )
	        fp_drop_written(p, fdes, fp);
	else
	        fp_drop(p, fdes, fp, 0);
	return(error);
}


int
rd_uio(p, fdes, uio, retval)
	struct proc *p;
	int fdes;
	register uio_t uio;
	user_ssize_t *retval;
{
	struct fileproc *fp;
	int error;
	user_ssize_t count;
#if KTRACE
	struct iovec_64 *ktriov = NULL;
	struct uio ktruio;
	int didktr = 0;
	u_int iovlen;
#endif

	if ( (error = preparefileread(p, &fp, fdes, 0)) )
	        return (error);

	count = uio_resid(uio);
#if KTRACE
	/*
	 * if tracing, save a copy of iovec
	 */
	if (KTRPOINT(p, KTR_GENIO)) {
		iovlen = uio->uio_iovcnt *
			(IS_64BIT_PROCESS(p) ? sizeof (struct iovec_64) : sizeof (struct iovec_32));
		MALLOC(ktriov, struct iovec_64 *, iovlen, M_TEMP, M_WAITOK);
		if (ktriov != NULL) {
			bcopy((caddr_t)uio->uio_iovs.iov64p, (caddr_t)ktriov, iovlen);
			ktruio = *uio;
			didktr = 1;
		}
	} 
#endif  
	error = fo_read(fp, uio, fp->f_cred, 0, p);

	if (error) {
	        if (uio_resid(uio) != count && (error == ERESTART ||
						error == EINTR || error == EWOULDBLOCK))
		        error = 0;
	}
	*retval = count - uio_resid(uio);

#if KTRACE
	if (didktr) {
		if (error == 0) {
			ktruio.uio_iovs.iov64p = ktriov; 
			uio_setresid(&ktruio, *retval);
			ktrgenio(p->p_tracep, fdes, UIO_READ, &ktruio, error);
		}
		FREE(ktriov, M_TEMP);
	}
#endif
	donefileread(p, fp, fdes);

	return (error);
}

/*
 * Ioctl system call
 *
 */
int
ioctl(struct proc *p, register struct ioctl_args *uap, __unused register_t *retval)
{
	struct fileproc *fp;
	register u_long com;
	int error = 0;
	register u_int size;
	caddr_t datap, memp;
	boolean_t is64bit;
	int tmp;
#define STK_PARAMS	128
	char stkbuf[STK_PARAMS];
	int fd = uap->fd;

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(cmd, CAST_DOWN(int, uap->com)); /* LP64todo: uap->com is a user-land long */
	AUDIT_ARG(addr, uap->data);

	is64bit = proc_is64bit(p);

	proc_fdlock(p);
	error = fp_lookup(p,fd,&fp,1);
	if (error)  {
		proc_fdunlock(p);
		return(error);
	}

	AUDIT_ARG(file, p, fp);

	if ((fp->f_flag & (FREAD | FWRITE)) == 0) {
			error = EBADF;
			goto out;
	}
		
#if NETAT
	/*
	 * ### LD 6/11/97 Hack Alert: this is to get AppleTalk to work
	 * while implementing an ATioctl system call
	 */
	{
		if (appletalk_inited && ((uap->com & 0x0000FFFF) == 0xff99)) {
			u_long  fixed_command;
#ifdef APPLETALK_DEBUG
			kprintf("ioctl: special AppleTalk \n");
#endif
			datap = &stkbuf[0];
			*(user_addr_t *)datap = uap->data;
			fixed_command = _IOW(0, 0xff99, uap->data);
			error = fo_ioctl(fp, fixed_command, datap, p);
			goto out;
		}
	}

#endif /* NETAT */


	switch (com = uap->com) {
	case FIONCLEX:
		*fdflags(p, uap->fd) &= ~UF_EXCLOSE;
		error =0;
		goto out;
	case FIOCLEX:
		*fdflags(p, uap->fd) |= UF_EXCLOSE;
		error =0;
		goto out;
	}

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if (size > IOCPARM_MAX) {
			error = ENOTTY;
			goto out;
	}
	memp = NULL;
	if (size > sizeof (stkbuf)) {
		proc_fdunlock(p);
		if ((memp = (caddr_t)kalloc(size)) == 0) {
			proc_fdlock(p);
			error = ENOMEM;
			goto out;
		}
		proc_fdlock(p);
		datap = memp;
	} else
		datap = &stkbuf[0];
	if (com&IOC_IN) {
		if (size) {
			proc_fdunlock(p);
			error = copyin(uap->data, datap, size);
			if (error) {
				if (memp)
					kfree(memp, size);
				proc_fdlock(p);
				goto out;
			}
			proc_fdlock(p);
		} else {
			/* XXX - IOC_IN and no size?  we should proably return an error here!! */
			if (is64bit) {
				*(user_addr_t *)datap = uap->data;
			}
			else {
				*(uint32_t *)datap = (uint32_t)uap->data;
			}
		}
	} else if ((com&IOC_OUT) && size)
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(datap, size);
	else if (com&IOC_VOID) {
		/* XXX - this is odd since IOC_VOID means no parameters */
		if (is64bit) {
			*(user_addr_t *)datap = uap->data;
		}
		else {
			*(uint32_t *)datap = (uint32_t)uap->data;
		}
	}

	switch (com) {

	case FIONBIO:
		if ( (tmp = *(int *)datap) )
			fp->f_flag |= FNONBLOCK;
		else
			fp->f_flag &= ~FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		break;

	case FIOASYNC:
		if ( (tmp = *(int *)datap) )
			fp->f_flag |= FASYNC;
		else
			fp->f_flag &= ~FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, p);
		break;

	case FIOSETOWN:
		tmp = *(int *)datap;
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			error = 0;
			break;
		}
		if (fp->f_type == DTYPE_PIPE) {
		        error = fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, p);
			break;
		}
		if (tmp <= 0) {
			tmp = -tmp;
		} else {
			struct proc *p1 = pfind(tmp);
			if (p1 == 0) {
				error = ESRCH;
				break;
			}
			tmp = p1->p_pgrp->pg_id;
		}
		error = fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, p);
		break;

	case FIOGETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			error = 0;
			*(int *)datap = ((struct socket *)fp->f_data)->so_pgid;
			break;
		}
		error = fo_ioctl(fp, TIOCGPGRP, datap, p);
		*(int *)datap = -*(int *)datap;
		break;

	default:
		error = fo_ioctl(fp, com, datap, p);
		/*
		 * Copy any data to user, size was
		 * already set and checked above.
		 */
		if (error == 0 && (com&IOC_OUT) && size)
			error = copyout(datap, uap->data, (u_int)size);
		break;
	}
	proc_fdunlock(p);
	if (memp)
		kfree(memp, size);
	proc_fdlock(p);
out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return(error);
}

int	selwait, nselcoll;
#define SEL_FIRSTPASS 1
#define SEL_SECONDPASS 2
extern int selcontinue(int error);
extern int selprocess(int error, int sel_pass);
static int selscan(struct proc *p, struct _select * sel,
			int nfd, register_t *retval, int sel_pass, wait_queue_sub_t wqsub);
static int selcount(struct proc *p, u_int32_t *ibits, u_int32_t *obits,
			int nfd, int * count);
static int seldrop(struct proc *p, u_int32_t *ibits, int nfd);
extern uint64_t	tvtoabstime(struct timeval	*tvp);

/*
 * Select system call.
 */
int
select(struct proc *p, struct select_args *uap, register_t *retval)
{
	int error = 0;
	u_int ni, nw, size;
	thread_t th_act;
	struct uthread	*uth;
	struct _select *sel;
	int needzerofill = 1;
	int count = 0;

	th_act = current_thread();
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_select;
	retval = (int *)get_bsduthreadrval(th_act);
	*retval = 0;

	if (uap->nd < 0) {
		return (EINVAL);
	}

	if (uap->nd > p->p_fd->fd_nfiles)
		uap->nd = p->p_fd->fd_nfiles; /* forgiving; slightly wrong */

	nw = howmany(uap->nd, NFDBITS);
	ni = nw * sizeof(fd_mask);

	/*
	 * if this is the first select by the thread 
	 * allocate the space for bits.
	 */
	if (sel->nbytes == 0) {
		sel->nbytes = 3 * ni;
		MALLOC(sel->ibits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK | M_ZERO);
		MALLOC(sel->obits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if ((sel->ibits == NULL) || (sel->obits == NULL))
			panic("select out of memory");
		needzerofill = 0;
	}

	/*
	 * if the previously allocated space for the bits
	 * is smaller than what is requested. Reallocate.
	 */
	if (sel->nbytes < (3 * ni)) {
		sel->nbytes = (3 * ni);
		FREE(sel->ibits, M_TEMP);
		FREE(sel->obits, M_TEMP);
		MALLOC(sel->ibits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK | M_ZERO);
		MALLOC(sel->obits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK | M_ZERO);
		if ((sel->ibits == NULL) || (sel->obits == NULL))
			panic("select out of memory");
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
			struct user_timeval atv64;
			error = copyin(uap->tv, (caddr_t)&atv64, sizeof(atv64));
			/* Loses resolution - assume timeout < 68 years */
			atv.tv_sec = atv64.tv_sec;
			atv.tv_usec = atv64.tv_usec;
		} else {
			error = copyin(uap->tv, (caddr_t)&atv, sizeof(atv));
		}
		if (error)
			goto continuation;
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto continuation;
		}

		clock_absolutetime_interval_to_deadline(
										tvtoabstime(&atv), &sel->abstime);
	}
	else
		sel->abstime = 0;

	if ( (error = selcount(p, sel->ibits, sel->obits, uap->nd, &count)) ) {
			goto continuation;
	}

	sel->count = count;
	size = SIZEOF_WAITQUEUE_SET + (count * SIZEOF_WAITQUEUE_LINK);
	if (sel->allocsize) {
		if (sel->wqset == 0)
			panic("select: wql memory smashed");
		/* needed for the select now */
		if (size > sel->allocsize) {
			kfree(sel->wqset,  sel->allocsize);
			sel->allocsize = size;
			sel->wqset = (wait_queue_set_t)kalloc(size);
			if (sel->wqset == (wait_queue_set_t)NULL)
				panic("failed to allocate memory for waitqueue\n");
		}
	} else {
		sel->count = count;
		sel->allocsize = size;
		sel->wqset = (wait_queue_set_t)kalloc(sel->allocsize);
		if (sel->wqset == (wait_queue_set_t)NULL)
			panic("failed to allocate memory for waitqueue\n");
	}
	bzero(sel->wqset, size);
	sel->wql = (char *)sel->wqset + SIZEOF_WAITQUEUE_SET;
	wait_queue_set_init(sel->wqset, (SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST));

continuation:
	return selprocess(error, SEL_FIRSTPASS);
}

int
selcontinue(int error)
{
	return selprocess(error, SEL_SECONDPASS);
}

int
selprocess(int error, int sel_pass)
{
	int ncoll;
	u_int ni, nw;
	thread_t th_act;
	struct uthread	*uth;
	struct proc *p;
	struct select_args *uap;
	int *retval;
	struct _select *sel;
	int unwind = 1;
	int prepost = 0;
	int somewakeup = 0;
	int doretry = 0;
	wait_result_t wait_result;

	p = current_proc();
	th_act = current_thread();
	uap = (struct select_args *)get_bsduthreadarg(th_act);
	retval = (int *)get_bsduthreadrval(th_act);
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_select;

	/* if it is first pass wait queue is not setup yet */
	if ((error != 0) && (sel_pass == SEL_FIRSTPASS))
			unwind = 0;
	if (sel->count == 0)
			unwind = 0;
retry:
	if (error != 0) {
	  goto done;
	}

	ncoll = nselcoll;
	p->p_flag |= P_SELECT;
	/* skip scans if the select is just for timeouts */
	if (sel->count) {
		if (sel_pass == SEL_FIRSTPASS)
			wait_queue_sub_clearrefs(sel->wqset);

		error = selscan(p, sel, uap->nd, retval, sel_pass, sel->wqset);
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
		if (now >= sel->abstime)
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
	if (uap->tv && sel->abstime == 0) {
		goto done;
	}

	/* No spurious wakeups due to colls,no need to check for them */
	 if ((sel_pass == SEL_SECONDPASS) || ((p->p_flag & P_SELECT) == 0)) {
		sel_pass = SEL_FIRSTPASS;
		goto retry;
	}

	p->p_flag &= ~P_SELECT;

	/* if the select is just for timeout skip check */
	if (sel->count &&(sel_pass == SEL_SECONDPASS))
		panic("selprocess: 2nd pass assertwaiting");

	/* Wait Queue Subordinate has waitqueue as first element */
	wait_result = wait_queue_assert_wait((wait_queue_t)sel->wqset,
					     &selwait, THREAD_ABORTSAFE, sel->abstime);
	if (wait_result != THREAD_AWAKENED) {
		/* there are no preposted events */
		error = tsleep1(NULL, PSOCK | PCATCH,
				"select", 0, selcontinue);
	} else  {
		prepost = 1;
		error = 0;
	}

	sel_pass = SEL_SECONDPASS;
	if (error == 0) {
		if (!prepost)
			somewakeup =1;
		goto retry;
	}
done:
	if (unwind) {
		wait_subqueue_unlink_all(sel->wqset);
		seldrop(p, sel->ibits, uap->nd);
	}
	p->p_flag &= ~P_SELECT;
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

static int
selscan(p, sel, nfd, retval, sel_pass, wqsub)
	struct proc *p;
	struct _select *sel;
	int nfd;
	register_t *retval;
	int sel_pass;
	wait_queue_sub_t wqsub;
{
	register struct filedesc *fdp = p->p_fd;
	register int msk, i, j, fd;
	register u_int32_t bits;
	struct fileproc *fp;
	int n = 0;
	int nc = 0;
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *optr;
	u_int nw;
	u_int32_t *ibits, *obits;
	char * wql;
	char * wql_ptr;

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
	wql = sel->wql;

	nw = howmany(nfd, NFDBITS);

	nc = 0;
	proc_fdlock(p);

	if (sel->count) {
		for (msk = 0; msk < 3; msk++) {
			iptr = (u_int32_t *)&ibits[msk * nw];
			optr = (u_int32_t *)&obits[msk * nw];

			for (i = 0; i < nfd; i += NFDBITS) {
				bits = iptr[i/NFDBITS];

				while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
					bits &= ~(1 << j);
					fp = fdp->fd_ofiles[fd];

					if (fp == NULL ||
						(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
						proc_fdunlock(p);
						return(EBADF);
					}
					if (sel_pass == SEL_SECONDPASS) {
						wql_ptr = (char *)0;
						fp->f_flags &= ~FP_INSELECT;
						fp->f_waddr = (void *)0;
					} else {
					        wql_ptr = (wql + nc * SIZEOF_WAITQUEUE_LINK);
						fp->f_flags |= FP_INSELECT;
						fp->f_waddr = (void *)wqsub;
					}
					if (fp->f_ops && fo_select(fp, flag[msk], wql_ptr, p)) {
						optr[fd/NFDBITS] |= (1 << (fd % NFDBITS));
						n++;
					}
					nc++;
				}
			}
		}
	}
	proc_fdunlock(p);
	*retval = n;
	return (0);
}

static int poll_callback(struct kqueue *, struct kevent *, void *);

struct poll_continue_args {
	user_addr_t pca_fds;
	u_int pca_nfds;
	u_int pca_rfds;
};

int
poll(struct proc *p, struct poll_args *uap, register_t *retval)
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
	    (nfds > p->p_rlimit[RLIMIT_NOFILE].rlim_cur && nfds > FD_SETSIZE))
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
	p->p_flag |= P_SELECT;

	for (i = 0; i < nfds; i++) {
		short events = fds[i].events;
		struct kevent kev;
		int kerror = 0;

		/* per spec, ignore fd values below zero */
		if (fds[i].fd < 0) {
			fds[i].revents = 0;
			continue;
		}

		/* convert the poll event into a kqueue kevent */
		kev.ident = fds[i].fd;
		kev.flags = EV_ADD | EV_ONESHOT | EV_POLL;
		kev.fflags = NOTE_LOWAT;
		kev.data = 1; /* efficiency be damned: any data should trigger */
		kev.udata = CAST_USER_ADDR_T(&fds[i]);

		/* Handle input events */
		if (events & ( POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND )) {
			kev.filter = EVFILT_READ;
			if (!(events & ( POLLIN | POLLRDNORM )))
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
	error = kevent_scan(kq, poll_callback, NULL, cont, &atv, p);
	rfds = cont->pca_rfds;

 done:
	p->p_flag &= ~P_SELECT;
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

	kqueue_dealloc(kq, p);
	return (error);
}

static int
poll_callback(__unused struct kqueue *kq, struct kevent *kevp, void *data)
{
	struct poll_continue_args *cont = (struct poll_continue_args *)data;
	struct pollfd *fds = CAST_DOWN(struct pollfd *, kevp->udata);
	short mask;

	/* convert the results back into revents */
	if (kevp->flags & EV_EOF)
		fds->revents |= POLLHUP;
	if (kevp->flags & EV_ERROR)
		fds->revents |= POLLERR;
	cont->pca_rfds++;

	switch (kevp->filter) {
	case EVFILT_READ:
		if (fds->revents & POLLHUP)
			mask = (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND );
		else {
			mask = 0;
			if (kevp->data != 0)
				mask |= (POLLIN | POLLRDNORM );
			if (kevp->flags & EV_OOBAND)
				mask |= ( POLLPRI | POLLRDBAND );
		}
		fds->revents |= (fds->events & mask);
		break;

	case EVFILT_WRITE:
		if (!(fds->revents & POLLHUP))
			fds->revents |= (fds->events & ( POLLOUT | POLLWRNORM | POLLWRBAND ));
		break;

	case EVFILT_PROC:
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
	return 0;
}
	
int
seltrue(__unused dev_t dev, __unused int flag, __unused struct proc *p)
{

	return (1);
}

static int
selcount(struct proc *p, u_int32_t *ibits, __unused u_int32_t *obits, 
		 int nfd, int *count)
{
	register struct filedesc *fdp = p->p_fd;
	register int msk, i, j, fd;
	register u_int32_t bits;
	struct fileproc *fp;
	int n = 0;
	u_int32_t *iptr;
	u_int nw;
	int error=0; 
	int dropcount;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*count=0;
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
				fp = fdp->fd_ofiles[fd];
				if (fp == NULL ||
					(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
						*count=0;
						error = EBADF;
						goto bad;
				}
				fp->f_iocount++;
				n++;
			}
		}
	}
	proc_fdunlock(p);

	*count = n;
	return (0);
bad:
	dropcount = 0;
	
	if (n== 0)
		goto out;
	/* undo the iocounts */
	for (msk = 0; msk < 3; msk++) {
		iptr = (u_int32_t *)&ibits[msk * nw];
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = iptr[i/NFDBITS];
			while ((j = ffs(bits)) && (fd = i + --j) < nfd) {
				bits &= ~(1 << j);
				fp = fdp->fd_ofiles[fd];
				if (dropcount >= n)
					goto out;
				fp->f_iocount--;

				if (p->p_fpdrainwait && fp->f_iocount == 0) {
				        p->p_fpdrainwait = 0;
					wakeup(&p->p_fpdrainwait);
				}
				dropcount++;
			}
		}
	}
out:
	proc_fdunlock(p);
	return(error);
}

static int
seldrop(p, ibits, nfd)
	struct proc *p;
	u_int32_t *ibits;
	int nfd;
{
	register struct filedesc *fdp = p->p_fd;
	register int msk, i, j, fd;
	register u_int32_t bits;
	struct fileproc *fp;
	int n = 0;
	u_int32_t *iptr;
	u_int nw;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
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
				fp = fdp->fd_ofiles[fd];
				if (fp == NULL 
#if 0
			/* if you are here then it is being closed */
					|| (fdp->fd_ofileflags[fd] & UF_RESERVED)
#endif
					) {
						proc_fdunlock(p);
						return(EBADF);
				}
				n++;
				fp->f_iocount--;
				fp->f_flags &= ~FP_INSELECT;

				if (p->p_fpdrainwait && fp->f_iocount == 0) {
				        p->p_fpdrainwait = 0;
					wakeup(&p->p_fpdrainwait);
				}
			}
		}
	}
	proc_fdunlock(p);
	return (0);
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

	if ((p_wql == (void *)0) && ((sip->si_flags & SI_INITED) == 0)) {
		return;
	}

	/*do not record if this is second pass of select */
	if((p_wql == (void *)0)) {
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
	if (!wait_queue_member(&sip->si_wait_queue, ut->uu_select.wqset))
		wait_queue_link_noalloc(&sip->si_wait_queue, ut->uu_select.wqset,
					(wait_queue_link_t)p_wql);

	return;
}

void
selwakeup(sip)
	register struct selinfo *sip;
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
		wait_queue_wakeup_all(&sip->si_wait_queue, &selwait, THREAD_AWAKENED);
		sip->si_flags &= ~SI_RECORDED;
	}

}

void 
selthreadclear(sip)
	register struct selinfo *sip;
{

	if ((sip->si_flags & SI_INITED) == 0) {
		return;
	}
	if (sip->si_flags & SI_RECORDED) {
			selwakeup(sip);
			sip->si_flags &= ~(SI_RECORDED | SI_COLL);
	}
	sip->si_flags |= SI_CLEAR;
	wait_queue_unlinkall_nofree(&sip->si_wait_queue);
}




#define DBG_EVENT	0x10

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

	KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_START, evq, evq->ee_flags, evq->ee_eventmask,0,0);

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
		      (pipep->pipe_buffer.size - pipep->pipe_buffer.cnt) >= PIPE_BUF) {

		          if (pipep->pipe_state & PIPE_EOF) {
			          mask |= EV_WR|EV_RESET;
				  break;
			  }
			  mask |= EV_WR;
			  evq->ee_req.er_wcnt = pipep->pipe_buffer.size - pipep->pipe_buffer.cnt;
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

			KERNEL_DEBUG(DBG_MISC_POST, evq, evq->ee_req.er_eventbits, mask, 1,0);

			evprocenque(evq);
		}
	}
	KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_END, 0,0,0,1,0);
}


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
		          if (sp->so_error) {
			          if ((sp->so_type == SOCK_STREAM) && ((sp->so_error == ECONNREFUSED) || (sp->so_error == ECONNRESET))) {
				          if ((sp->so_pcb == 0) || (((struct inpcb *)sp->so_pcb)->inp_state == INPCB_STATE_DEAD) || !(tp = sototcpcb(sp)) ||
					      (tp->t_state == TCPS_CLOSED)) {
					          mask |= EV_RE|EV_RESET;
						  break;
					  }
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
		          if (sp->so_error) {
			          if ((sp->so_type == SOCK_STREAM) && ((sp->so_error == ECONNREFUSED) || (sp->so_error == ECONNRESET))) {
				          if ((sp->so_pcb == 0) || (((struct inpcb *)sp->so_pcb)->inp_state == INPCB_STATE_DEAD) || !(tp = sototcpcb(sp)) ||
					      (tp->t_state == TCPS_CLOSED)) {
					          mask |= EV_WR|EV_RESET;
						  break;
					  }
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


/*
 * watchevent system call. user passes us an event to watch
 * for. we malloc an event object, initialize it, and queue
 * it to the open socket. when the event occurs, postevent()
 * will enque it back to our proc where we can retrieve it
 * via waitevent().
 *
 * should this prevent duplicate events on same socket?
 */
int
watchevent(proc_t p, struct watchevent_args *uap, __unused int *retval)
{
	struct eventqelt *evq = (struct eventqelt *)0;
	struct eventqelt *np = NULL;
	struct eventreq *erp;
	struct fileproc *fp = NULL;
	int error;

	KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_START, 0,0,0,0,0);

	// get a qelt and fill with users req
	MALLOC(evq, struct eventqelt *, sizeof(struct eventqelt), M_TEMP, M_WAITOK);

	if (evq == NULL)
	        panic("can't MALLOC evq");
	erp = &evq->ee_req;

	// get users request pkt
	if ( (error = copyin(CAST_USER_ADDR_T(uap->u_req), (caddr_t)erp,
			   sizeof(struct eventreq))) ) {
		FREE(evq, M_TEMP);

		KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, error,0,0,0,0);
		return(error);
	}
	KERNEL_DEBUG(DBG_MISC_WATCH, erp->er_handle,uap->u_eventmask,evq,0,0);

	// validate, freeing qelt if errors
	error = 0;
	proc_fdlock(p);

	if (erp->er_type != EV_FD) {
		error = EINVAL;
	} else if ((error = fp_lookup(p, erp->er_handle, &fp, 1)) != 0) {
		error = EBADF;
	} else if (fp->f_type == DTYPE_SOCKET) {
		socket_lock((struct socket *)fp->f_data, 1);
		np = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
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
			if (fp->f_type == DTYPE_SOCKET)
				socket_unlock((struct socket *)fp->f_data, 1);
			else 
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

	if (fp->f_type == DTYPE_SOCKET) {
		TAILQ_INSERT_TAIL(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
		postevent((struct socket *)fp->f_data, 0, EV_RWBYTES); // catch existing events

		socket_unlock((struct socket *)fp->f_data, 1);
	} else {
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
 * or poll mode (tv=NULL);
 */
int
waitevent(proc_t p, struct waitevent_args *uap, int *retval)
{
        int error = 0;
	struct eventqelt *evq;
	struct eventreq   er;
	uint64_t abstime, interval;

	if (uap->tv) {
		struct timeval atv;

		error = copyin(CAST_USER_ADDR_T(uap->tv), (caddr_t)&atv, sizeof (atv));
		if (error)
			return(error);
		if (itimerfix(&atv)) {
			error = EINVAL;
			return(error);
		}
		interval = tvtoabstime(&atv);
	} else
		interval = 0;

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
	        bcopy((caddr_t)&evq->ee_req, (caddr_t)&er, sizeof (struct eventreq));

	        TAILQ_REMOVE(&p->p_evlist, evq, ee_plist);

		evq->ee_flags &= ~EV_QUEUED;

		proc_unlock(p);

		error = copyout((caddr_t)&er, CAST_USER_ADDR_T(uap->u_req), sizeof(struct eventreq));

		KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, error,
			     evq->ee_req.er_handle,evq->ee_req.er_eventbits,evq,0);
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

		KERNEL_DEBUG(DBG_MISC_WAIT, 1,&p->p_evlist,0,0,0);

		error = msleep1(&p->p_evlist, &p->p_mlock, (PSOCK | PCATCH), "waitevent", abstime);

		KERNEL_DEBUG(DBG_MISC_WAIT, 2,&p->p_evlist,0,0,0);

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
	struct eventreq er;
	struct eventreq *erp = &er;
	struct eventqelt *evq;
	int error;
	struct fileproc *fp;
	int flag;

	KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_START, 0,0,0,0,0);

	/*
	 * get user's request pkt
	 */
	if ((error = copyin(CAST_USER_ADDR_T(uap->u_req), (caddr_t)erp,
			     sizeof(struct eventreq)))) {
			KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, error,0,0,0,0);
	        return(error);
	}
	proc_fdlock(p);

	if (erp->er_type != EV_FD) {
		error = EINVAL;
	} else if ((error = fp_lookup(p, erp->er_handle, &fp, 1)) != 0) {
		error = EBADF;
	} else if (fp->f_type == DTYPE_SOCKET) {
		socket_lock((struct socket *)fp->f_data, 1);
		evq = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
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
		if (fp->f_type == DTYPE_SOCKET) 
			socket_unlock((struct socket *)fp->f_data, 1);
		else 
			PIPE_UNLOCK((struct pipe *)fp->f_data);
		fp_drop(p, erp->er_handle, fp, 0);
		KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, EINVAL,0,0,0,0);
		return(EINVAL);
	}
	KERNEL_DEBUG(DBG_MISC_MOD, erp->er_handle,uap->u_eventmask,evq,0,0);

	if (uap->u_eventmask == EV_RM) {
		EVPROCDEQUE(p, evq);

		if (fp->f_type == DTYPE_SOCKET) {
			TAILQ_REMOVE(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
			socket_unlock((struct socket *)fp->f_data, 1);
		} else {
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
		if (fp->f_type == DTYPE_SOCKET) 
			socket_unlock((struct socket *)fp->f_data, 1);
		else 
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

	if (fp->f_type == DTYPE_SOCKET) {
		postevent((struct socket *)fp->f_data, 0, flag);
		socket_unlock((struct socket *)fp->f_data, 1);
	}
	else {
		postpipeevent((struct pipe *)fp->f_data, flag);
		PIPE_UNLOCK((struct pipe *)fp->f_data);
	}
	fp_drop(p, erp->er_handle, fp, 0);
	KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, evq->ee_req.er_handle,evq->ee_eventmask,fp->f_data,flag,0);
	return(0);
}

/* this routine is called from the close of fd with proc_fdlock held */
int
waitevent_close(struct proc *p, struct fileproc *fp)
{
	struct eventqelt *evq;


	fp->f_flags &= ~FP_WAITEVENT;

	if (fp->f_type == DTYPE_SOCKET) {
	        socket_lock((struct socket *)fp->f_data, 1);
		evq = ((struct socket *)fp->f_data)->so_evlist.tqh_first;
	}
	else if (fp->f_type == DTYPE_PIPE) {
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
	        if (fp->f_type == DTYPE_SOCKET) 
		        socket_unlock((struct socket *)fp->f_data, 1);
		else 
		        PIPE_UNLOCK((struct pipe *)fp->f_data);

		proc_fdlock(p);

		return(EINVAL);
	}
	EVPROCDEQUE(p, evq);

	if (fp->f_type == DTYPE_SOCKET) {
		TAILQ_REMOVE(&((struct socket *)fp->f_data)->so_evlist, evq, ee_slist);
		socket_unlock((struct socket *)fp->f_data, 1);
	} else {
		TAILQ_REMOVE(&((struct pipe *)fp->f_data)->pipe_evlist, evq, ee_slist);
		PIPE_UNLOCK((struct pipe *)fp->f_data);
	}
	FREE(evq, M_TEMP);

	proc_fdlock(p);

	return(0);
}

