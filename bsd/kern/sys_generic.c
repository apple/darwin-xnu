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
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>
#include <sys/malloc.h>

#include <sys/mount.h>
#include <sys/protosw.h>
#include <sys/ev.h>
#include <sys/user.h>
#include <sys/kdebug.h>
#include <kern/assert.h>
#include <kern/thread_act.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/syscall.h>

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
#if KTRACE 
#include <sys/ktrace.h>
#endif
#include <sys/vnode.h>


__private_extern__ struct file*
holdfp(fdp, fd, flag) 
	struct filedesc* fdp;
	int fd, flag;
{
	struct file* fp;

	if (((u_int)fd) >= fdp->fd_nfiles ||
		(fp = fdp->fd_ofiles[fd]) == NULL ||
		(fp->f_flag & flag) == 0) {
			return (NULL);
	}
	if (fref(fp) == -1)
		return (NULL);
	return (fp);   
}

/*
 * Read system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct read_args {
	int fd;
	char *cbuf;
	u_int nbyte;
};
#endif
int
read(p, uap, retval)
	struct proc *p;
	register struct read_args *uap;
	register_t *retval;
{
	register struct file *fp;
	int error;

	if ((fp = holdfp(p->p_fd, uap->fd, FREAD)) == NULL)
		return (EBADF);
	error = dofileread(p, fp, uap->fd, uap->cbuf, uap->nbyte,
			(off_t)-1, 0, retval);
	frele(fp);
	return(error);
}

/* 
 * Pread system call
 */
#ifndef _SYS_SYSPROTO_H_
struct pread_args {
	int     fd;
	void    *buf;
	size_t  nbyte;
#ifdef DOUBLE_ALIGN_PARAMS
	int     pad;
#endif
	off_t   offset;
};
#endif
int
pread(p, uap, retval)
	struct proc *p;
	register struct pread_args *uap;
	int *retval;
{
	register struct file *fp;
	int error;

	if ((fp = holdfp(p->p_fd, uap->fd, FREAD)) == NULL)
		return (EBADF);
	if (fp->f_type != DTYPE_VNODE) {
		error = ESPIPE;
	} else {
		error = dofileread(p, fp, uap->fd, uap->buf, uap->nbyte,
				uap->offset, FOF_OFFSET, retval);
	}
	frele(fp);
	
	if (!error)
	    KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pread) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);
	
	return(error);
}

/*
 * Code common for read and pread
 */
__private_extern__ int
dofileread(p, fp, fd, buf, nbyte, offset, flags, retval)
	struct proc *p;
	struct file *fp;
	int fd, flags;
	void *buf;
	size_t nbyte;
	off_t offset;
	int *retval;
{
	struct uio auio;
	struct iovec aiov;
	long cnt, error = 0;
#if KTRACE
	struct iovec ktriov;
	struct uio ktruio;
	int didktr = 0;
#endif

	aiov.iov_base = (caddr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = offset;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
#if KTRACE
	/*
	* if tracing, save a copy of iovec
	*/
	if (KTRPOINT(p, KTR_GENIO)) {
		ktriov = aiov;
		ktruio = auio;
		didktr = 1;
	}
#endif
	cnt = nbyte;

	if ((error = fo_read(fp, &auio, fp->f_cred, flags, p))) {
		if (auio.uio_resid != cnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
	cnt -= auio.uio_resid;
#if KTRACE
	if (didktr && error == 0) {
		ktruio.uio_iov = &ktriov;
		ktruio.uio_resid = cnt;
		ktrgenio(p->p_tracep, fd, UIO_READ, &ktruio, error,
		    KERNEL_FUNNEL);
	}
#endif  
	*retval = cnt;
	return (error);
}

/*      
 * Scatter read system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct readv_args {
	int fd;
	struct iovec *iovp;
	u_int iovcnt;
};
#endif
int
readv(p, uap, retval)
	struct proc *p;
	register struct readv_args *uap;
	int *retval;
{
	struct uio auio;
	register struct iovec *iov;
	int error;
	struct iovec aiov[UIO_SMALLIOV];

	if (uap->iovcnt > UIO_SMALLIOV) {
		if (uap->iovcnt > UIO_MAXIOV)
			return (EINVAL);	
		if ((iov = (struct iovec *)
			    kalloc(sizeof(struct iovec) * (uap->iovcnt))) == 0)
			return (ENOMEM);
	} else
		iov = aiov;
	auio.uio_iov = iov;
	auio.uio_iovcnt = uap->iovcnt;
	auio.uio_rw = UIO_READ;
	error = copyin((caddr_t)uap->iovp, (caddr_t)iov,
	    uap->iovcnt * sizeof (struct iovec));
	if (!error)
		error = rwuio(p, uap->fd, &auio, UIO_READ, retval);
	if (uap->iovcnt > UIO_SMALLIOV)
		kfree(iov, sizeof(struct iovec)*uap->iovcnt);
	return (error);
}

/*
 * Write system call
 */
#ifndef _SYS_SYSPROTO_H_
struct write_args {
	int fd;
	char *cbuf;
	u_int nbyte;
};
#endif
int
write(p, uap, retval)
	struct proc *p;
	register struct write_args *uap;
	int *retval;
{
	register struct file *fp;
	int error;      

	if ((fp = holdfp(p->p_fd, uap->fd, FWRITE)) == NULL)
		return (EBADF);
	error = dofilewrite(p, fp, uap->fd, uap->cbuf, uap->nbyte,
			(off_t)-1, 0, retval);
	frele(fp);
	return(error);  
}

/*                          
 * Pwrite system call
 */
#ifndef _SYS_SYSPROTO_H_
struct pwrite_args {
	int     fd;
	const void *buf;
	size_t  nbyte;
#ifdef DOUBLE_ALIGN_PARAMS
	int     pad;
#endif
	off_t   offset;
};      
#endif
int
pwrite(p, uap, retval)
	struct proc *p;
	register struct pwrite_args *uap;
	int *retval;	
{
        register struct file *fp;
        int error; 

        if ((fp = holdfp(p->p_fd, uap->fd, FWRITE)) == NULL)
                return (EBADF);
        if (fp->f_type != DTYPE_VNODE) {
                error = ESPIPE;
        } else {
            error = dofilewrite(p, fp, uap->fd, uap->buf, uap->nbyte,
                uap->offset, FOF_OFFSET, retval);
        }
        frele(fp);

	if (!error)
	    KERNEL_DEBUG_CONSTANT((BSDDBG_CODE(DBG_BSD_SC_EXTENDED_INFO, SYS_pwrite) | DBG_FUNC_NONE),
	      uap->fd, uap->nbyte, (unsigned int)((uap->offset >> 32)), (unsigned int)(uap->offset), 0);
	
        return(error);
}

__private_extern__ int                  
dofilewrite(p, fp, fd, buf, nbyte, offset, flags, retval)
	struct proc *p;
	struct file *fp; 
	int fd, flags;
	const void *buf;
	size_t nbyte;   
	off_t offset; 
	int *retval;
{       
	struct uio auio;
	struct iovec aiov;
	long cnt, error = 0;
#if KTRACE
	struct iovec ktriov;
	struct uio ktruio;
	int didktr = 0; 
#endif
        
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;   
	auio.uio_offset = offset;
	if (nbyte > INT_MAX)   
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
#if KTRACE
	/*
	* if tracing, save a copy of iovec and uio
	*/
	if (KTRPOINT(p, KTR_GENIO)) {
		ktriov = aiov;
		ktruio = auio;
		didktr = 1;
	}
#endif  
	cnt = nbyte; 
	if (fp->f_type == DTYPE_VNODE)
		bwillwrite();
	if ((error = fo_write(fp, &auio, fp->f_cred, flags, p))) {
		if (auio.uio_resid != cnt && (error == ERESTART ||
			error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET)
			psignal(p, SIGPIPE);
	}
	cnt -= auio.uio_resid;
#if KTRACE 
	if (didktr && error == 0) {
		ktruio.uio_iov = &ktriov;
		ktruio.uio_resid = cnt;
		ktrgenio(p->p_tracep, fd, UIO_WRITE, &ktruio, error,
		    KERNEL_FUNNEL);
	}
#endif  
	*retval = cnt;
	return (error); 
}
        
/*      
 * Gather write system call  
 */     
#ifndef _SYS_SYSPROTO_H_
struct writev_args {
	int fd;
	struct iovec *iovp;
	u_int iovcnt;
};
#endif
int
writev(p, uap, retval)
	struct proc *p;
	register struct writev_args *uap;
	int *retval;
{
	struct uio auio;
	register struct iovec *iov;
	int error;
	struct iovec aiov[UIO_SMALLIOV];

	if (uap->iovcnt > UIO_SMALLIOV) {
		if (uap->iovcnt > UIO_MAXIOV)
			return (EINVAL);	
		if ((iov = (struct iovec *)
			    kalloc(sizeof(struct iovec) * (uap->iovcnt))) == 0)
			return (ENOMEM);
	} else
		iov = aiov;
	auio.uio_iov = iov;
	auio.uio_iovcnt = uap->iovcnt;
	auio.uio_rw = UIO_WRITE;
	error = copyin((caddr_t)uap->iovp, (caddr_t)iov,
	    uap->iovcnt * sizeof (struct iovec));
	if (!error)
		error = rwuio(p, uap->fd, &auio, UIO_WRITE, retval);
	if (uap->iovcnt > UIO_SMALLIOV)
		kfree(iov, sizeof(struct iovec)*uap->iovcnt);
	return (error);
}

int
rwuio(p, fdes, uio, rw, retval)
	struct proc *p;
	int fdes;
	register struct uio *uio;
	enum uio_rw rw;
	int *retval;
{
	struct file *fp;
	register struct iovec *iov;
	int i, count, flag, error;
#if KTRACE
	struct iovec *ktriov;
	struct uio ktruio;
	int didktr = 0;
	u_int iovlen;
#endif

	if (error = fdgetf(p, fdes, &fp))
		return (error);

	if ((fp->f_flag&(rw==UIO_READ ? FREAD : FWRITE)) == 0) {
		return(EBADF);
	}
	uio->uio_resid = 0;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_procp = p;
	iov = uio->uio_iov;
	for (i = 0; i < uio->uio_iovcnt; i++) {
		if (iov->iov_len < 0) {
			return(EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		if (uio->uio_resid < 0) {
			return(EINVAL);
		}
		iov++;
	}
	count = uio->uio_resid;
#if KTRACE
	/*
	 * if tracing, save a copy of iovec
	 */
	if (KTRPOINT(p, KTR_GENIO)) {
		iovlen = uio->uio_iovcnt * sizeof (struct iovec);
		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy((caddr_t)uio->uio_iov, (caddr_t)ktriov, iovlen);
		ktruio = *uio;
		didktr = 1;
	} 
#endif  

	if (rw == UIO_READ) {
		if (error = fo_read(fp, uio, fp->f_cred, 0, p))
			if (uio->uio_resid != count && (error == ERESTART ||
				error == EINTR || error == EWOULDBLOCK))
				error = 0;
	} else {
		if (fp->f_type == DTYPE_VNODE)
			bwillwrite();
		if (error = fo_write(fp, uio, fp->f_cred, 0, p)) {
			if (uio->uio_resid != count && (error == ERESTART ||
				error == EINTR || error == EWOULDBLOCK))
				error = 0;
                        /* The socket layer handles SIGPIPE */
			if (error == EPIPE && fp->f_type != DTYPE_SOCKET)
				psignal(p, SIGPIPE);
		}
	}

	*retval = count - uio->uio_resid;

#if KTRACE
	if (didktr) {
		if (error == 0) {
			ktruio.uio_iov = ktriov; 
			ktruio.uio_resid = *retval;
			ktrgenio(p->p_tracep, fdes, rw, &ktruio, error,
			    KERNEL_FUNNEL);
		}
		FREE(ktriov, M_TEMP);
	}
#endif

	return(error);
}

/*
 * Ioctl system call
 */
#ifndef _SYS_SYSPROTO_H_
struct ioctl_args {
	int fd;
	u_long com;
	caddr_t data;
};
#endif
int
ioctl(p, uap, retval)
	struct proc *p;
	register struct ioctl_args *uap;
	register_t *retval;
{
	struct file *fp;
	register u_long com;
	register int error;
	register u_int size;
	caddr_t data, memp;
	int tmp;
#define STK_PARAMS	128
	char stkbuf[STK_PARAMS];

	if (error = fdgetf(p, uap->fd, &fp))
		return (error);

	if ((fp->f_flag & (FREAD | FWRITE)) == 0)
		return (EBADF);
		
#if NETAT
	/*
	 * ### LD 6/11/97 Hack Alert: this is to get AppleTalk to work
	 * while implementing an ATioctl system call
	 */
	{
		extern int appletalk_inited;

		if (appletalk_inited && ((uap->com & 0x0000FFFF) == 0xff99)) {
#ifdef APPLETALK_DEBUG
			kprintf("ioctl: special AppleTalk \n");
#endif
			error = fo_ioctl(fp, uap->com, uap->data, p);
			return(error);
		}
	}

#endif /* NETAT */


	switch (com = uap->com) {
	case FIONCLEX:
		*fdflags(p, uap->fd) &= ~UF_EXCLOSE;
		return (0);
	case FIOCLEX:
		*fdflags(p, uap->fd) |= UF_EXCLOSE;
		return (0);
	}

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if (size > IOCPARM_MAX)
		return (ENOTTY);
	memp = NULL;
	if (size > sizeof (stkbuf)) {
		if ((memp = (caddr_t)kalloc(size)) == 0)
			return(ENOMEM);
		data = memp;
	} else
		data = stkbuf;
	if (com&IOC_IN) {
		if (size) {
			error = copyin(uap->data, data, (u_int)size);
			if (error) {
				if (memp)
					kfree(memp, size);
				return (error);
			}
		} else
			*(caddr_t *)data = uap->data;
	} else if ((com&IOC_OUT) && size)
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(data, size);
	else if (com&IOC_VOID)
		*(caddr_t *)data = uap->data;

	switch (com) {

	case FIONBIO:
		if (tmp = *(int *)data)
			fp->f_flag |= FNONBLOCK;
		else
			fp->f_flag &= ~FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		break;

	case FIOASYNC:
		if (tmp = *(int *)data)
			fp->f_flag |= FASYNC;
		else
			fp->f_flag &= ~FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, p);
		break;

	case FIOSETOWN:
		tmp = *(int *)data;
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			error = 0;
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
			*(int *)data = ((struct socket *)fp->f_data)->so_pgid;
			break;
		}
		error = fo_ioctl(fp, TIOCGPGRP, data, p);
		*(int *)data = -*(int *)data;
		break;

	default:
		error = fo_ioctl(fp, com, data, p);
		/*
		 * Copy any data to user, size was
		 * already set and checked above.
		 */
		if (error == 0 && (com&IOC_OUT) && size)
			error = copyout(data, uap->data, (u_int)size);
		break;
	}
	if (memp)
		kfree(memp, size);
	return (error);
}

int	selwait, nselcoll;
#define SEL_FIRSTPASS 1
#define SEL_SECONDPASS 2
extern int selcontinue(int error);
extern int selprocess(int error, int sel_pass);
static int selscan(struct proc *p, struct _select * sel,
			int nfd, register_t *retval, int sel_pass);
static int selcount(struct proc *p, u_int32_t *ibits, u_int32_t *obits,
			int nfd, int * count, int * nfcount);
extern uint64_t	tvtoabstime(struct timeval	*tvp);

/*
 * Select system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct select_args {
	int nd;
	u_int32_t *in;
	u_int32_t *ou;
	u_int32_t *ex;
	struct timeval *tv;
};
#endif
int
select(p, uap, retval)
	register struct proc *p;
	register struct select_args *uap;
	register_t *retval;
{
	int error = 0;
	u_int ni, nw, size;
	thread_act_t th_act;
	struct uthread	*uth;
	struct _select *sel;
	int needzerofill = 1;
	int kfcount =0;
	int nfcount = 0;
	int count = 0;

	th_act = current_act();
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_state.ss_select;
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
		MALLOC(sel->ibits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK);
		MALLOC(sel->obits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK);
		bzero((caddr_t)sel->ibits, sel->nbytes);
		bzero((caddr_t)sel->obits, sel->nbytes);
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
		MALLOC(sel->ibits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK);
		MALLOC(sel->obits, u_int32_t *, sel->nbytes, M_TEMP, M_WAITOK);
		bzero((caddr_t)sel->ibits, sel->nbytes);
		bzero((caddr_t)sel->obits, sel->nbytes);
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
		if (uap->name && (error = copyin((caddr_t)uap->name, \
			(caddr_t)&sel->ibits[(x) * nw], ni))) \
			goto continuation; \
	} while (0)

	getbits(in, 0);
	getbits(ou, 1);
	getbits(ex, 2);
#undef	getbits

	if (uap->tv) {
		struct timeval atv;

		error = copyin((caddr_t)uap->tv, (caddr_t)&atv, sizeof (atv));
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

	sel->nfcount = 0;
	if (error = selcount(p, sel->ibits, sel->obits, uap->nd, &count, &nfcount)) {
			goto continuation;
	}

	sel->nfcount = nfcount;
	sel->count = count;
	size = SIZEOF_WAITQUEUE_SUB + (count * SIZEOF_WAITQUEUE_LINK);
	if (sel->allocsize) {
		if (uth->uu_wqsub == 0)
			panic("select: wql memory smashed");
		/* needed for the select now */
		if (size > sel->allocsize) {
			kfree(uth->uu_wqsub,  sel->allocsize);
			sel->allocsize = size;
			uth->uu_wqsub = (wait_queue_sub_t)kalloc(sel->allocsize);
			if (uth->uu_wqsub == (wait_queue_sub_t)NULL)
				panic("failed to allocate memory for waitqueue\n");
			sel->wql = (char *)uth->uu_wqsub + SIZEOF_WAITQUEUE_SUB;
		}
	} else {
		sel->count = count;
		sel->allocsize = size;
		uth->uu_wqsub = (wait_queue_sub_t)kalloc(sel->allocsize);
		if (uth->uu_wqsub == (wait_queue_sub_t)NULL)
			panic("failed to allocate memory for waitqueue\n");
		sel->wql = (char *)uth->uu_wqsub + SIZEOF_WAITQUEUE_SUB;
	}
	bzero(uth->uu_wqsub, size);
	wait_queue_sub_init(uth->uu_wqsub, (SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST));

continuation:
	return selprocess(error, SEL_FIRSTPASS);
}

int
selcontinue(int error)
{
	return selprocess(error, SEL_SECONDPASS);
}

int
selprocess(error, sel_pass)
{
	int ncoll;
	u_int ni, nw;
	thread_act_t th_act;
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
	th_act = current_act();
	uap = (struct select_args *)get_bsduthreadarg(th_act);
	retval = (int *)get_bsduthreadrval(th_act);
	uth = get_bsdthread_info(th_act);
	sel = &uth->uu_state.ss_select;

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
			wait_queue_sub_clearrefs(uth->uu_wqsub);

		error = selscan(p, sel, uap->nd, retval, sel_pass);
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
	wait_result = wait_queue_assert_wait((wait_queue_t)uth->uu_wqsub,
										 &selwait, THREAD_ABORTSAFE);
	if (wait_result != THREAD_AWAKENED) {
		/* there are no preposted events */
        error = tsleep1(NULL, PSOCK | PCATCH,
									"select", sel->abstime, selcontinue);
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
	if (unwind)
		wait_subqueue_unlink_all(uth->uu_wqsub);
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
		if (uap->name && (error2 = copyout((caddr_t)&sel->obits[(x) * nw], \
			(caddr_t)uap->name, ni))) \
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
selscan(p, sel, nfd, retval, sel_pass)
	struct proc *p;
	struct _select *sel;
	int nfd;
	register_t *retval;
	int sel_pass;
{
	register struct filedesc *fdp = p->p_fd;
	register int msk, i, j, fd;
	register u_int32_t bits;
	struct file *fp;
	int n = 0;
	int nc = 0;
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *optr;
	u_int nw;
	u_int32_t *ibits, *obits;
	char * wql;
	int nfunnel = 0;
	int count, nfcount;
	char * wql_ptr;
	struct vnode *vp;

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

	count = sel->count;
	nfcount = sel->nfcount;

	if (nfcount > count)
		panic("selcount count<nfcount");

	nw = howmany(nfd, NFDBITS);

	nc = 0;
	if ( nfcount < count) {
		/* some or all in kernel funnel */
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
						return(EBADF);
					}
					if (sel_pass == SEL_SECONDPASS)
						wql_ptr = (char *)0;
					else
						wql_ptr = (wql+ nc * SIZEOF_WAITQUEUE_LINK);
					/*
					 * Merlot: need to remove the bogus f_data check
					 * from the following "if" statement.  It's there
					 * because of various problems stemming from 
					 * races due to the split-funnels and lack of real
					 * referencing on sockets...
					 */
					if (fp->f_ops && (fp->f_type != DTYPE_SOCKET)
					        && (fp->f_data != (caddr_t)-1) 
						&& !(fp->f_type == DTYPE_VNODE 
							&& (vp = (struct vnode *)fp->f_data) 
							&& vp->v_type == VFIFO)
						&& fo_select(fp, flag[msk], wql_ptr, p)) {
						optr[fd/NFDBITS] |= (1 << (fd % NFDBITS));
						n++;
					}
					nc++;
				}
			}
		}
	}

	if (nfcount) {
		/* socket file descriptors for scan */
		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);

		nc = 0;
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
						thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
						return(EBADF);
					}
					if (sel_pass == SEL_SECONDPASS)
						wql_ptr = (char *)0;
					else
						wql_ptr = (wql+ nc * SIZEOF_WAITQUEUE_LINK);
					if (fp->f_ops 
						&& (fp->f_type == DTYPE_SOCKET
							|| (fp->f_type == DTYPE_VNODE 
					        	&& (vp = (struct vnode *)fp->f_data)  
							&& vp != (struct vnode *)-1 
							&& vp->v_type == VFIFO))
						&& fo_select(fp, flag[msk], wql_ptr, p)) {
						optr[fd/NFDBITS] |= (1 << (fd % NFDBITS));
						n++;
					}
					nc++;
				}
			}
		}
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	}

	*retval = n;
	return (0);
}

/*ARGSUSED*/
int
seltrue(dev, flag, p)
	dev_t dev;
	int flag;
	struct proc *p;
{

	return (1);
}

static int
selcount(p, ibits, obits, nfd, count, nfcount)
	struct proc *p;
	u_int32_t *ibits, *obits;
	int nfd;
	int *count;
	int *nfcount;
{
	register struct filedesc *fdp = p->p_fd;
	register int msk, i, j, fd;
	register u_int32_t bits;
	struct file *fp;
	int n = 0;
	int nc = 0;
	int nfc = 0;
	static int flag[3] = { FREAD, FWRITE, 0 };
	u_int32_t *iptr, *fptr, *fbits;
	u_int nw;
	struct vnode *vp;

	/*
	 * Problems when reboot; due to MacOSX signal probs
	 * in Beaker1C ; verify that the p->p_fd is valid
	 */
	if (fdp == NULL) {
		*count=0;
		*nfcount=0;
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
				if (fp == NULL ||
					(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
						*count=0;
						*nfcount=0;
						return(EBADF);
				}
				if (fp->f_type == DTYPE_SOCKET || 
					(fp->f_type == DTYPE_VNODE 
						&& (vp = (struct vnode *)fp->f_data)  
						&& vp->v_type == VFIFO))
					nfc++;
				n++;
			}
		}
	}
	*count = n;
	*nfcount = nfc;
	return (0);
}

/*
 * Record a select request.
 */
void
selrecord(selector, sip, p_wql)
	struct proc *selector;
	struct selinfo *sip;
	void * p_wql;
{
	thread_act_t	cur_act = current_act();
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
	if (!wait_queue_member(&sip->si_wait_queue, ut->uu_wqsub))
		wait_queue_link_noalloc(&sip->si_wait_queue, ut->uu_wqsub, (wait_queue_link_t)p_wql);

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


extern struct eventqelt *evprocdeque(struct proc *p, struct eventqelt *eqp);

/*
 * called upon socket close. deque and free all events for
 * the socket
 */
void
evsofree(struct socket *sp)
{
  struct eventqelt *eqp, *next;

  if (sp == NULL) return;

  for (eqp = sp->so_evlist.tqh_first; eqp != NULL; eqp = next) {
    next = eqp->ee_slist.tqe_next;
    evprocdeque(eqp->ee_proc, eqp); // remove from proc q if there
    TAILQ_REMOVE(&sp->so_evlist, eqp, ee_slist); // remove from socket q
    FREE(eqp, M_TEMP);
  }
}


#define DBG_EVENT 0x10

#define DBG_POST 0x10
#define DBG_WATCH 0x11
#define DBG_WAIT 0x12
#define DBG_MOD 0x13
#define DBG_EWAKEUP 0x14
#define DBG_ENQUEUE 0x15
#define DBG_DEQUEUE 0x16

#define DBG_MISC_POST MISCDBG_CODE(DBG_EVENT,DBG_POST)
#define DBG_MISC_WATCH MISCDBG_CODE(DBG_EVENT,DBG_WATCH)
#define DBG_MISC_WAIT MISCDBG_CODE(DBG_EVENT,DBG_WAIT)
#define DBG_MISC_MOD MISCDBG_CODE(DBG_EVENT,DBG_MOD)
#define DBG_MISC_EWAKEUP MISCDBG_CODE(DBG_EVENT,DBG_EWAKEUP)
#define DBG_MISC_ENQUEUE MISCDBG_CODE(DBG_EVENT,DBG_ENQUEUE)
#define DBG_MISC_DEQUEUE MISCDBG_CODE(DBG_EVENT,DBG_DEQUEUE)


/*
 * enque this event if it's not already queued. wakeup
   the proc if we do queue this event to it.
 */
void
evprocenque(struct eventqelt *eqp)
{
  struct proc *p;

  assert(eqp);
  KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_START, eqp, eqp->ee_flags, eqp->ee_eventmask,0,0);
  if (eqp->ee_flags & EV_QUEUED) {
    KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
    return;
  }
  eqp->ee_flags |= EV_QUEUED;
  eqp->ee_eventmask = 0;  // disarm
  p = eqp->ee_proc;
  TAILQ_INSERT_TAIL(&p->p_evlist, eqp, ee_plist);
  KERNEL_DEBUG(DBG_MISC_EWAKEUP,0,0,0,eqp,0);
  wakeup(&p->p_evlist);
  KERNEL_DEBUG(DBG_MISC_ENQUEUE|DBG_FUNC_END, 0,0,0,0,0);
}

/*
 * given either a sockbuf or a socket run down the
 * event list and queue ready events found
 */
void
postevent(struct socket *sp, struct sockbuf *sb, int event)
{
  int mask;
  struct eventqelt *evq;
  register struct tcpcb *tp;

  if (sb) sp = sb->sb_so;
  if (!sp || sp->so_evlist.tqh_first == NULL) return;

  KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_START, event,0,0,0,0);

  for (evq = sp->so_evlist.tqh_first;
       evq != NULL; evq = evq->ee_slist.tqe_next) {

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

    case EV_RWBYTES:
    case EV_OOB:
    case EV_RWBYTES|EV_OOB:
      if (event & EV_OOB) {
      if ((evq->ee_eventmask & EV_EX)) {
	if (sp->so_oobmark || ((sp->so_state & SS_RCVATMARK))) {
	  mask |= EV_EX|EV_OOB;
	}
      }
      }
      if (event & EV_RWBYTES) {
      if ((evq->ee_eventmask & EV_RE) && soreadable(sp)) {
	if ((sp->so_type == SOCK_STREAM) && (sp->so_error == ECONNREFUSED) ||
	    (sp->so_error == ECONNRESET)) {
	  if ((sp->so_pcb == 0) ||
	      !(tp = sototcpcb(sp)) ||
	      (tp->t_state == TCPS_CLOSED)) {
	    mask |= EV_RE|EV_RESET;
	    break;
	  }
	}
	if (sp->so_state & SS_CANTRCVMORE) {
	  mask |= EV_RE|EV_FIN;
	  evq->ee_req.er_rcnt = sp->so_rcv.sb_cc;
	  break;
	}
	mask |= EV_RE;
	evq->ee_req.er_rcnt = sp->so_rcv.sb_cc;
      }

      if ((evq->ee_eventmask & EV_WR) && sowriteable(sp)) {
	if ((sp->so_type == SOCK_STREAM) &&(sp->so_error == ECONNREFUSED) ||
	    (sp->so_error == ECONNRESET)) {
	  if ((sp->so_pcb == 0) ||
	      !(tp = sototcpcb(sp)) ||
	      (tp->t_state == TCPS_CLOSED)) {
	  mask |= EV_WR|EV_RESET;
	  break;
	  }
	}
	mask |= EV_WR;
	evq->ee_req.er_wcnt = sbspace(&sp->so_snd);
      }
      }
    break;

    case EV_RCONN:
      if ((evq->ee_eventmask & EV_RE)) {
	evq->ee_req.er_rcnt = sp->so_qlen + 1;  // incl this one
	mask |= EV_RE|EV_RCONN;
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
      return;
    } /* switch */

    if (mask) {
      evq->ee_req.er_eventbits |= mask;
      KERNEL_DEBUG(DBG_MISC_POST, evq, evq->ee_req.er_eventbits, mask,0,0);
      evprocenque(evq);
    }
  }
  KERNEL_DEBUG(DBG_MISC_POST|DBG_FUNC_END, 0,0,0,0,0);
}

/*
 * remove and return the first event (eqp=NULL) or a specific
 * event, or return NULL if no events found
 */
struct eventqelt *
evprocdeque(struct proc *p, struct eventqelt *eqp)
{
  
  KERNEL_DEBUG(DBG_MISC_DEQUEUE|DBG_FUNC_START,p,eqp,0,0,0);

  if (eqp && ((eqp->ee_flags & EV_QUEUED) == NULL)) {
    KERNEL_DEBUG(DBG_MISC_DEQUEUE|DBG_FUNC_END,0,0,0,0,0);
    return(NULL);
  }
  if (p->p_evlist.tqh_first == NULL) {
    KERNEL_DEBUG(DBG_MISC_DEQUEUE|DBG_FUNC_END,0,0,0,0,0);
    return(NULL);
  }
  if (eqp == NULL) {  // remove first
    eqp = p->p_evlist.tqh_first;
  }
  TAILQ_REMOVE(&p->p_evlist, eqp, ee_plist);
  eqp->ee_flags &= ~EV_QUEUED;
  KERNEL_DEBUG(DBG_MISC_DEQUEUE|DBG_FUNC_END,eqp,0,0,0,0);
  return(eqp);
}

struct evwatch_args {
  struct eventreq  *u_req;
  int               u_eventmask;
};


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
watchevent(p, uap, retval)
     struct proc *p;
     struct evwatch_args *uap;
     register_t *retval;
{
  struct eventqelt *eqp = (struct eventqelt *)0;
  struct eventqelt *np;
  struct eventreq *erp;
  struct file *fp;
  struct socket *sp;
  int error;

  KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_START, 0,0,0,0,0);

  // get a qelt and fill with users req
  MALLOC(eqp, struct eventqelt *, sizeof(struct eventqelt), M_TEMP, M_WAITOK);
  if (!eqp) panic("can't MALLOC eqp");
  erp = &eqp->ee_req;
  // get users request pkt
  if (error = copyin((caddr_t)uap->u_req, (caddr_t)erp,
		     sizeof(struct eventreq))) {
    FREE(eqp, M_TEMP);
    KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, error,0,0,0,0);
    return(error);
  }
  KERNEL_DEBUG(DBG_MISC_WATCH, erp->er_handle,uap->u_eventmask,eqp,0,0);
  // validate, freeing qelt if errors
  error = 0;
  if (erp->er_type != EV_FD) {
    error = EINVAL;
  } else  if (erp->er_handle < 0) {
    error = EBADF;
  } else  if (erp->er_handle > p->p_fd->fd_nfiles) {
    error = EBADF;
  } else if ((fp = *fdfile(p, erp->er_handle)) == NULL) {
    error = EBADF;
  } else if (fp->f_type != DTYPE_SOCKET) {
    error = EINVAL;
  }
  if (error) {
    FREE(eqp,M_TEMP);
    KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, error,0,0,0,0);
    return(error);
  }

  erp->er_rcnt = erp->er_wcnt = erp->er_eventbits = 0;
  eqp->ee_proc = p;
  eqp->ee_eventmask = uap->u_eventmask & EV_MASK;
  eqp->ee_flags = 0;

  sp = (struct socket *)fp->f_data;
  assert(sp != NULL);

  // only allow one watch per file per proc
  for (np = sp->so_evlist.tqh_first; np != NULL; np = np->ee_slist.tqe_next) {
    if (np->ee_proc == p) {
      FREE(eqp,M_TEMP);
      KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, EINVAL,0,0,0,0);
      return(EINVAL);
    }
  }

  TAILQ_INSERT_TAIL(&sp->so_evlist, eqp, ee_slist);
  postevent(sp, 0, EV_RWBYTES); // catch existing events
  KERNEL_DEBUG(DBG_MISC_WATCH|DBG_FUNC_END, 0,0,0,0,0);
  return(0);
}

struct evwait_args {
  struct eventreq *u_req;
  struct timeval *tv;
};

/*
 * waitevent system call.
 * grabs the next waiting event for this proc and returns
 * it. if no events, user can request to sleep with timeout
 * or poll mode (tv=NULL);
 */
int
waitevent(p, uap, retval)
	struct proc *p;
	struct evwait_args *uap;
	register_t *retval;
{
	int error = 0;
	struct eventqelt *eqp;
	uint64_t abstime, interval;

	if (uap->tv) {
		struct timeval atv;

		error = copyin((caddr_t)uap->tv, (caddr_t)&atv, sizeof (atv));
		if (error)
			return(error);
		if (itimerfix(&atv)) {
			error = EINVAL;
			return(error);
		}

		interval = tvtoabstime(&atv);
	}
	else
		abstime = interval = 0;

	KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_START, 0,0,0,0,0);

retry:
	if ((eqp = evprocdeque(p,NULL)) != NULL) {
		error = copyout((caddr_t)&eqp->ee_req,
								(caddr_t)uap->u_req, sizeof(struct eventreq));
		KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, error,
						eqp->ee_req.er_handle,eqp->ee_req.er_eventbits,eqp,0);

		return (error);
	}
	else {
		if (uap->tv && interval == 0) {
			*retval = 1;  // poll failed
			KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, error,0,0,0,0);

			return (error);
		}

		if (interval != 0)
			clock_absolutetime_interval_to_deadline(interval, &abstime);

		KERNEL_DEBUG(DBG_MISC_WAIT, 1,&p->p_evlist,0,0,0);
		error = tsleep1(&p->p_evlist, PSOCK | PCATCH,
									"waitevent", abstime, (int (*)(int))0);
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

	KERNEL_DEBUG(DBG_MISC_WAIT|DBG_FUNC_END, 0,0,0,0,0);

	return (error);
}

struct modwatch_args {
  struct eventreq *u_req;
  int               u_eventmask;
};

/*
 * modwatch system call. user passes in event to modify.
 * if we find it we reset the event bits and que/deque event
 * it needed.
 */
int
modwatch(p, uap, retval)
     struct proc *p;
     struct modwatch_args *uap;
     register_t *retval;
{
  struct eventreq er;
  struct eventreq *erp = &er;
  struct eventqelt *evq;
  int error;
  struct file *fp;
  struct socket *sp;
  int flag;

  KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_START, 0,0,0,0,0);

  // get users request pkt
  if (error = copyin((caddr_t)uap->u_req, (caddr_t)erp,
		     sizeof(struct eventreq))) return(error);

  if (erp->er_type != EV_FD) return(EINVAL);
  if (erp->er_handle < 0) return(EBADF);
  if (erp->er_handle > p->p_fd->fd_nfiles) return(EBADF);
  if ((fp = *fdfile(p, erp->er_handle)) == NULL)
    return(EBADF);
  if (fp->f_type != DTYPE_SOCKET) return(EINVAL); // for now must be sock
  sp = (struct socket *)fp->f_data;

  /* soo_close sets f_data to 0 before switching funnel */
  if (sp == (struct socket *)0) 
    return(EBADF);

  // locate event if possible
  for (evq = sp->so_evlist.tqh_first;
       evq != NULL; evq = evq->ee_slist.tqe_next) {
    if (evq->ee_proc == p) break;
  }

  if (evq == NULL) {
	KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, EINVAL,0,0,0,0);
    return(EINVAL);
  }
  KERNEL_DEBUG(DBG_MISC_MOD, erp->er_handle,uap->u_eventmask,evq,0,0);

    if (uap->u_eventmask == EV_RM) {
    evprocdeque(p, evq);
    TAILQ_REMOVE(&sp->so_evlist, evq, ee_slist);
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
    return(EINVAL);
  }

   evq->ee_eventmask = uap->u_eventmask & EV_MASK;
   evprocdeque(p, evq);
   evq->ee_req.er_eventbits = 0;
   postevent(sp, 0, flag);
   KERNEL_DEBUG(DBG_MISC_MOD|DBG_FUNC_END, evq->ee_req.er_handle,evq->ee_eventmask,sp,flag,0);
   return(0);
}
