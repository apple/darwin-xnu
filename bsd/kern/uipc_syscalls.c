/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1982, 1986, 1989, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * sendfile(2) and related extensions:
 * Copyright (c) 1998, David Greenman. All rights reserved. 
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
 *	@(#)uipc_syscalls.c	8.4 (Berkeley) 2/21/94
 */



#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <kern/lock.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/kernel.h>
#include <sys/uio_internal.h>

#include <bsm/audit_kernel.h>

#include <sys/kdebug.h>
#include <sys/sysproto.h>

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
#if KDEBUG

#define DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETSOCK, 0)
#define DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETSOCK, 2)
#define DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETSOCK, 1)
#define DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETSOCK, 3)
#define DBG_FNC_SENDMSG		NETDBG_CODE(DBG_NETSOCK, (1 << 8) | 1)
#define DBG_FNC_SENDTO		NETDBG_CODE(DBG_NETSOCK, (2 << 8) | 1)
#define DBG_FNC_SENDIT		NETDBG_CODE(DBG_NETSOCK, (3 << 8) | 1)
#define DBG_FNC_RECVFROM	NETDBG_CODE(DBG_NETSOCK, (5 << 8))
#define DBG_FNC_RECVMSG		NETDBG_CODE(DBG_NETSOCK, (6 << 8))
#define DBG_FNC_RECVIT		NETDBG_CODE(DBG_NETSOCK, (7 << 8))

#endif


#define HACK_FOR_4056224 1
#if HACK_FOR_4056224
static pid_t last_pid_4056224 = 0;
#endif /* HACK_FOR_4056224 */


#if SENDFILE
static void sf_buf_init(void *arg);
SYSINIT(sock_sf, SI_SUB_MBUF, SI_ORDER_ANY, sf_buf_init, NULL)
static struct sf_buf *sf_buf_alloc(void);
static void sf_buf_ref(caddr_t addr, u_int size);
static void sf_buf_free(caddr_t addr, u_int size);

static SLIST_HEAD(, sf_buf) sf_freelist;
static vm_offset_t sf_base;
static struct sf_buf *sf_bufs;
static int sf_buf_alloc_want;
#endif

static int sendit(struct proc *p, int s, struct user_msghdr *mp, uio_t uiop, 
					int flags, register_t *retval);
static int recvit(struct proc *p, int s, struct user_msghdr *mp, uio_t uiop,
					user_addr_t namelenp, register_t *retval);
  
static int accept1(struct proc *p, struct accept_args *uap, register_t *retval, int compat);
static int getsockname1(struct proc *p, struct getsockname_args *uap,
			     register_t *retval, int compat);
static int getpeername1(struct proc *p, struct getpeername_args *uap,
			     register_t *retval, int compat);


#if COMPAT_43_SOCKET
struct orecvmsg_args  {
	int	s;
	struct	omsghdr *msg;
	int	flags;
};
struct osendmsg_args {
	int s;
	caddr_t msg;
	int flags;
};
struct osend_args {
	int s;
	caddr_t buf;
	int len;
	int flags;
};
struct	orecv_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};

int oaccept(struct proc *p, struct accept_args *uap, register_t *retval);
int ogetpeername(struct proc *p, struct getpeername_args *uap, register_t *retval);
int ogetsockname(struct proc *p, struct getsockname_args *uap, register_t *retval);
int orecv(struct proc *p, struct orecv_args	*uap, register_t *retval);
int orecvfrom(struct proc *p, struct recvfrom_args *uap, register_t *retval);
int orecvmsg(struct proc *p, struct orecvmsg_args *uap, register_t *retval);
int	osend(struct proc *p, struct osend_args *uap, register_t *retval);
int osendmsg(struct proc *p, struct osendmsg_args *uap, register_t *retval);
#endif // COMPAT_43_SOCKET

/*
 * System call interface to the socket abstraction.
 */

extern	struct fileops socketops;

int
socket(p, uap, retval)
	struct proc *p;
	register struct socket_args *uap;
	register_t *retval;
{
	struct socket *so;
	struct fileproc *fp;
	int fd, error;

	AUDIT_ARG(socket, uap->domain, uap->type, uap->protocol);

	error = falloc(p, &fp, &fd);
	if (error) {
		return (error);
	}
	fp->f_flag = FREAD|FWRITE;
	fp->f_type = DTYPE_SOCKET;
	fp->f_ops = &socketops;

	error = socreate(uap->domain, &so, uap->type, uap->protocol);
	if (error) {
		fp_free(p, fd, fp);
	} else {
		fp->f_data = (caddr_t)so;

		proc_fdlock(p);
		*fdflags(p, fd) &= ~UF_RESERVED;
		
		fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);

		*retval = fd;
	}
	return (error);
}

/* ARGSUSED */
int
bind(struct proc *p, struct bind_args *uap, __unused register_t *retval)
{
	struct sockaddr *sa;
	struct socket *so;
	int error;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error) 
		goto out;
	AUDIT_ARG(sockaddr, p, sa);
	if (so != NULL)	
		error = sobind(so, sa);
	else
		error = EBADF;
	FREE(sa, M_SONAME);
out:
	file_drop(uap->s);
	return (error);
}


int
listen(__unused struct proc *p, register struct listen_args *uap, 
		__unused register_t *retval)
{
	int error;
	struct socket * so;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	if (so != NULL)
		error =  solisten(so, uap->backlog);
	else
		error = EBADF;
	file_drop(uap->s);
	return (error);
}

#if !COMPAT_43_SOCKET
#define	accept1	accept
#endif



int
accept1(struct proc *p, struct accept_args *uap, register_t *retval, int compat)
{
	struct fileproc *fp;
	struct sockaddr *sa;
	socklen_t namelen;
	int error;
	struct socket *head, *so = NULL;
	lck_mtx_t *mutex_held;
	int fd = uap->s;
	int newfd;;
	short fflag;		/* type must match fp->f_flag */
	int dosocklock = 0;

	AUDIT_ARG(fd, uap->s);
	if (uap->name) {
		error = copyin(uap->anamelen, (caddr_t)&namelen,
			sizeof(socklen_t));
		if(error)
			return (error);
	}
	error = fp_getfsock(p, fd, &fp, &head);
	if (error) {
		if (error == EOPNOTSUPP)
			error = ENOTSOCK;
		return (error);
	}
	if (head == NULL) {
		error = EBADF;
		goto out;
	}

	socket_lock(head, 1);

	if (head->so_proto->pr_getlock != NULL)  {
		mutex_held = (*head->so_proto->pr_getlock)(head, 0);
		dosocklock = 1;
	}
	else {
		mutex_held = head->so_proto->pr_domain->dom_mtx;
		dosocklock = 0;
	}


	if ((head->so_options & SO_ACCEPTCONN) == 0) {
		socket_unlock(head, 1);
		error = EINVAL;
		goto out;
	}
	if ((head->so_state & SS_NBIO) && head->so_comp.tqh_first == NULL) {
		socket_unlock(head, 1);
		error = EWOULDBLOCK;
		goto out;
	}
        while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_state & SS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		if (head->so_usecount < 1)
			panic("accept1: head=%x refcount=%d\n", head, head->so_usecount);
		error = msleep((caddr_t)&head->so_timeo, mutex_held, PSOCK | PCATCH,
		    "accept", 0);
		if (head->so_usecount < 1)
			panic("accept1: 2 head=%x refcount=%d\n", head, head->so_usecount);
		if ((head->so_state & SS_DRAINING)) {
			error = ECONNABORTED;
		}
		if (error) {
			socket_unlock(head, 1);
			goto out;
		}
	}
	if (head->so_error) {
		error = head->so_error;
		head->so_error = 0;
		socket_unlock(head, 1);
		goto out;
	}


	/*
	 * At this point we know that there is at least one connection
	 * ready to be accepted. Remove it from the queue prior to
	 * allocating the file descriptor for it since falloc() may
	 * block allowing another process to accept the connection
	 * instead.
	 */
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	so = TAILQ_FIRST(&head->so_comp);
	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	socket_unlock(head, 0); /* unlock head to avoid deadlock with select, keep a ref on head */
	fflag = fp->f_flag;
	proc_fdlock(p);
	error = falloc_locked(p, &fp, &newfd, 1);
	if (error) {
		/*
		 * Probably ran out of file descriptors. Put the
		 * unaccepted connection back onto the queue and
		 * do another wakeup so some other process might
		 * have a chance at it.
		 */
		proc_fdunlock(p);
		socket_lock(head, 0);
		TAILQ_INSERT_HEAD(&head->so_comp, so, so_list);
		head->so_qlen++;
		wakeup_one((caddr_t)&head->so_timeo);
		socket_unlock(head, 1);
		goto out;
	} 
	*fdflags(p, newfd) &= ~UF_RESERVED;
	*retval = newfd;
	fp->f_type = DTYPE_SOCKET;
	fp->f_flag = fflag;
	fp->f_ops = &socketops;
	fp->f_data = (caddr_t)so;
	fp_drop(p, newfd, fp, 1);
	proc_fdunlock(p);
	socket_lock(head, 0);
	if (dosocklock)
		socket_lock(so, 1);
	so->so_state &= ~SS_COMP;
	so->so_head = NULL;
	sa = 0;
	(void) soacceptlock(so, &sa, 0);
	socket_unlock(head, 1);
	if (sa == 0) {
		namelen = 0;
		if (uap->name)
			goto gotnoname;
		if (dosocklock)
			socket_unlock(so, 1);
		error = 0;
		goto out;
	}
	AUDIT_ARG(sockaddr, p, sa);
	if (uap->name) {
		/* check sa_len before it is destroyed */
		if (namelen > sa->sa_len)
			namelen = sa->sa_len;
#if COMPAT_43_SOCKET
		if (compat)
			((struct osockaddr *)sa)->sa_family =
			    sa->sa_family;
#endif
		error = copyout(sa, uap->name, namelen);
		if (!error)
gotnoname:
			error = copyout((caddr_t)&namelen, uap->anamelen, 
			    			sizeof(socklen_t));
	}
	FREE(sa, M_SONAME);
	if (dosocklock)
		socket_unlock(so, 1);
out:
	file_drop(fd);
	return (error);
}

int
accept(struct proc *p, struct accept_args *uap, register_t *retval)
{

	return (accept1(p, uap, retval, 0));
}

#if COMPAT_43_SOCKET
int
oaccept(struct proc *p, struct accept_args *uap, register_t *retval)
{

	return (accept1(p, uap, retval, 1));
}
#endif /* COMPAT_43_SOCKET */

/* ARGSUSED */
int
connect(struct proc *p, struct connect_args *uap, __unused register_t *retval)
{
	struct socket *so;
	struct sockaddr *sa;
	lck_mtx_t *mutex_held;
	int error;
	int fd = uap->s;

	AUDIT_ARG(fd, uap->s);
	error = file_socket( fd, &so);
	if (error)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}

	socket_lock(so, 1);

	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		socket_unlock(so, 1);
		error = EALREADY;
		goto out;
	}
	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error)  {
		socket_unlock(so, 1);
		goto out;
	}
	AUDIT_ARG(sockaddr, p, sa);
	error = soconnectlock(so, sa, 0);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		FREE(sa, M_SONAME);
		socket_unlock(so, 1);
		error = EINPROGRESS;
		goto out;
	}
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		if (so->so_proto->pr_getlock != NULL) 
			mutex_held = (*so->so_proto->pr_getlock)(so, 0);
		else 
			mutex_held = so->so_proto->pr_domain->dom_mtx;
		error = msleep((caddr_t)&so->so_timeo, mutex_held, PSOCK | PCATCH,
		    "connec", 0);
		if ((so->so_state & SS_DRAINING)) {
			error = ECONNABORTED;
		}
		if (error)
			break;
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
bad:
	so->so_state &= ~SS_ISCONNECTING;
	socket_unlock(so, 1);
	FREE(sa, M_SONAME);
	if (error == ERESTART)
		error = EINTR;
out:
	file_drop(fd);
	return (error);
}

int
socketpair(struct proc *p, struct socketpair_args *uap, __unused register_t *retval)
{
	struct fileproc *fp1, *fp2;
	struct socket *so1, *so2;
	int fd, error, sv[2];

	AUDIT_ARG(socket, uap->domain, uap->type, uap->protocol);
	error = socreate(uap->domain, &so1, uap->type, uap->protocol);
	if (error)
		return (error);
	error = socreate(uap->domain, &so2, uap->type, uap->protocol);
	if (error)
		goto free1;

	error = falloc(p, &fp1, &fd);
	if (error) {
		goto free2;
	}
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_type = DTYPE_SOCKET;
	fp1->f_ops = &socketops;
	fp1->f_data = (caddr_t)so1;
	sv[0] = fd;

	error = falloc(p, &fp2, &fd);
	if (error) {
		goto free3;
	}
	fp2->f_flag = FREAD|FWRITE;
	fp2->f_type = DTYPE_SOCKET;
	fp2->f_ops = &socketops;
	fp2->f_data = (caddr_t)so2;
	sv[1] = fd;

	error = soconnect2(so1, so2);
	if (error) {
		goto free4;
	}
	if (uap->type == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		 error = soconnect2(so2, so1);
		 if (error) {
			 goto free4;
		 }
	}

	proc_fdlock(p);
	*fdflags(p, sv[0]) &= ~UF_RESERVED;
	*fdflags(p, sv[1]) &= ~UF_RESERVED;
	fp_drop(p, sv[0], fp1, 1);
	fp_drop(p, sv[1], fp2, 1);
	proc_fdunlock(p);

	error = copyout((caddr_t)sv, uap->rsv, 2 * sizeof(int));
#if 0   /* old pipe(2) syscall compatability, unused these days */
	retval[0] = sv[0];		/* XXX ??? */
	retval[1] = sv[1];		/* XXX ??? */
#endif /* 0 */
	return (error);
free4:
	fp_free(p, sv[1], fp2);
free3:
	fp_free(p, sv[0], fp1);
free2:
	(void)soclose(so2);
free1:
	(void)soclose(so1);
	return (error);
}

static int
sendit(struct proc *p, int s, struct user_msghdr *mp, uio_t uiop, 
		int flags, register_t *retval)
{
	struct mbuf *control;
	struct sockaddr *to;
	int error;
	struct socket *so;
	user_ssize_t len;
#if KTRACE
	uio_t ktruio = NULL;
#endif
	
	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_START, 0,0,0,0,0);

	error = file_socket(s, &so);
	if (error )
	{
	    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
	    return (error);
	}
	
	if (mp->msg_name) {
		error = getsockaddr(&to, mp->msg_name, mp->msg_namelen);
		if (error) {
		    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
			goto out;
		}
		AUDIT_ARG(sockaddr, p, to);
	} else {
		to = 0;
	}
	if (mp->msg_control) {
		if (mp->msg_controllen < ((socklen_t)sizeof(struct cmsghdr))
#if COMPAT_43_SOCKET
		    && !(mp->msg_flags & MSG_COMPAT)
#endif
		) {
			error = EINVAL;
			goto bad;
		}
		error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL);
		if (error)
			goto bad;
#if COMPAT_43_SOCKET
		if (mp->msg_flags & MSG_COMPAT) {
			register struct cmsghdr *cm;

			M_PREPEND(control, sizeof(*cm), M_WAIT);
			if (control == 0) {
				error = ENOBUFS;
				goto bad;
			} else {
				cm = mtod(control, struct cmsghdr *);
				cm->cmsg_len = control->m_len;
				cm->cmsg_level = SOL_SOCKET;
				cm->cmsg_type = SCM_RIGHTS;
			}
		}
#endif
	} else {
		control = 0;
	}

#if KTRACE    
	if (KTRPOINT(p, KTR_GENIO)) {
		ktruio = uio_duplicate(uiop);
	}
#endif

	len = uio_resid(uiop);
	if (so == NULL)
		error = EBADF;
	else
		error = so->so_proto->pr_usrreqs->pru_sosend(so, to, uiop, 0, control,
							     flags);
	if (error) {
		if (uio_resid(uiop) != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
                /* Generation of SIGPIPE can be controlled per socket */
		if (error == EPIPE && !(so->so_flags & SOF_NOSIGPIPE))
			psignal(p, SIGPIPE);
	}
	if (error == 0)
		*retval = (int)(len - uio_resid(uiop));
bad:
#if KTRACE
	if (ktruio != NULL) {
		if (error == 0) {
			uio_setresid(ktruio, retval[0]);
			ktrgenio(p->p_tracep, s, UIO_WRITE, ktruio, error);
		}
		uio_free(ktruio);
	}
#endif
	if (to)
		FREE(to, M_SONAME);
	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
out:
	file_drop(s);
	return (error);
}


int
sendto(struct proc *p, struct sendto_args *uap, register_t *retval)
{
	struct user_msghdr msg;
	int error;
	uio_t auio = NULL;

	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_START, 0,0,0,0,0);
	AUDIT_ARG(fd, uap->s);

	auio = uio_create(1, 0,
				  (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
				  UIO_WRITE);
	if (auio == NULL) {
		return (ENOMEM);
	}
	uio_addiov(auio, uap->buf, uap->len);

	msg.msg_name = uap->to;
	msg.msg_namelen = uap->tolen;
	/* no need to set up msg_iov.  sendit uses uio_t we send it */
	msg.msg_iov = 0;
	msg.msg_iovlen = 0;
	msg.msg_control = 0;
	msg.msg_flags = 0;

	error = sendit(p, uap->s, &msg, auio, uap->flags, retval);
	
	if (auio != NULL) {
		uio_free(auio);
	}
	
#if HACK_FOR_4056224
	/* 
	 * Radar 4056224 
	 * Temporary workaround to let send() and recv() work over a pipe for binary compatibility
	 * This will be removed in the release following Tiger
	 */
	if (error == ENOTSOCK) {
		struct fileproc *fp;
		
        if (fp_lookup(p, uap->s, &fp, 0) == 0) {
			(void) fp_drop(p, uap->s, fp,0);
			
			if (fp->f_type == DTYPE_PIPE) {
				struct write_args write_uap;
				user_ssize_t write_retval;
				
				if (p->p_pid > last_pid_4056224) {
					last_pid_4056224 = p->p_pid;

					printf("%s[%d] uses send/recv on a pipe\n", 
						p->p_comm, p->p_pid);
				}
				
				bzero(&write_uap, sizeof(struct write_args));
				write_uap.fd = uap->s;
				write_uap.cbuf = uap->buf;
				write_uap.nbyte = uap->len;
	
				error = write(p, &write_uap, &write_retval);
				*retval = (int)write_retval;
			}
		}
	}
#endif /* HACK_FOR_4056224 */

	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_END, error, *retval,0,0,0);
	
	return(error);
}

#if COMPAT_43_SOCKET
int
osend(__unused struct proc *p, 
	  __unused struct osend_args *uap, 
	  __unused register_t *retval)
{
	/* these are no longer supported and in fact 
	 * there is no way to call it directly.
	 * LP64todo - remove this once we're sure there are no clients 
	 */
	return (ENOTSUP);
}

int
osendmsg(__unused struct proc *p, 
	  	 __unused struct osendmsg_args *uap, 
		 __unused register_t *retval)
{
	/* these are no longer supported and in fact 
	 * there is no way to call it directly.
	 * LP64todo - remove this once we're sure there are no clients 
	 */
	return (ENOTSUP);
}
#endif


int
sendmsg(struct proc *p, register struct sendmsg_args *uap, register_t *retval)
{
	struct msghdr msg;
	struct user_msghdr user_msg;
	caddr_t msghdrp;
	int	size_of_msghdr;
	int error;
	int size_of_iovec;
	uio_t auio = NULL;
	struct user_iovec *iovp;

	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_START, 0,0,0,0,0);
	AUDIT_ARG(fd, uap->s);
	if (IS_64BIT_PROCESS(p)) {
		msghdrp = (caddr_t) &user_msg;
		size_of_msghdr = sizeof(user_msg);
		size_of_iovec = sizeof(struct user_iovec);
	}
	else {
		msghdrp = (caddr_t) &msg;
		size_of_msghdr = sizeof(msg);
		size_of_iovec = sizeof(struct iovec);
	}
	error = copyin(uap->msg, msghdrp, size_of_msghdr);
	if (error)
	{
	    KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error,0,0,0,0);
	    return (error);
	}

	/* only need to copy if user process is not 64-bit */
	if (!IS_64BIT_PROCESS(p)) {
		user_msg.msg_flags = msg.msg_flags;
		user_msg.msg_controllen = msg.msg_controllen;
		user_msg.msg_control = CAST_USER_ADDR_T(msg.msg_control);
		user_msg.msg_iovlen = msg.msg_iovlen;
		user_msg.msg_iov = CAST_USER_ADDR_T(msg.msg_iov);
		user_msg.msg_namelen = msg.msg_namelen;
		user_msg.msg_name = CAST_USER_ADDR_T(msg.msg_name);
	}

	if (user_msg.msg_iovlen <= 0 || user_msg.msg_iovlen > UIO_MAXIOV) {
		KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, EMSGSIZE,0,0,0,0);
		return (EMSGSIZE);
	}

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(user_msg.msg_iovlen, 0,
				  (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
				  UIO_WRITE);
	if (auio == NULL) {
		error = ENOBUFS;
		goto done;
	}
		
	if (user_msg.msg_iovlen) {
		/* get location of iovecs within the uio.  then copyin the iovecs from
		 * user space.
		 */
		iovp = uio_iovsaddr(auio);
		if (iovp == NULL) {
			error = ENOBUFS;
			goto done;
		}
		error = copyin(user_msg.msg_iov, (caddr_t)iovp, (user_msg.msg_iovlen * size_of_iovec));
		if (error)
			goto done;
		user_msg.msg_iov = CAST_USER_ADDR_T(iovp);
	
		/* finish setup of uio_t */ 
		uio_calculateresid(auio);
	}
	else {
		user_msg.msg_iov = 0;
	}
	
#if COMPAT_43_SOCKET
	user_msg.msg_flags = 0;
#endif
	error = sendit(p, uap->s, &user_msg, auio, uap->flags, retval);
done:
	if (auio != NULL) {
		uio_free(auio);
	}
	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error,0,0,0,0);

	return (error);
}

static int
recvit(p, s, mp, uiop, namelenp, retval)
	register struct proc *p;
	int s;
	register struct user_msghdr *mp;
	uio_t uiop;
	user_addr_t namelenp;
	register_t *retval;
{
	int len, error;
	struct mbuf *m, *control = 0;
	user_addr_t ctlbuf;
	struct socket *so;
	struct sockaddr *fromsa = 0;
	struct fileproc *fp;
#if KTRACE
	uio_t ktruio = NULL;
#endif

	KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_START, 0,0,0,0,0);
	proc_fdlock(p);
	if ( (error = fp_lookup(p, s, &fp, 1)) ) {
	    KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, error,0,0,0,0);
		proc_fdunlock(p);
	    return (error);
	}
	if (fp->f_type != DTYPE_SOCKET) {
		fp_drop(p, s, fp,1);
		proc_fdunlock(p);
		return(ENOTSOCK);
	}

	so = (struct socket *)fp->f_data;	

	proc_fdunlock(p);
	if (uio_resid(uiop) < 0) {
		KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, EINVAL,0,0,0,0);
		error = EINVAL;
		goto out1;
	}
#if KTRACE
	if (KTRPOINT(p, KTR_GENIO)) {
		ktruio = uio_duplicate(uiop);
	}
#endif

	len = uio_resid(uiop);
	if (so == NULL)
		error = EBADF;
	else {
		error = so->so_proto->pr_usrreqs->pru_soreceive(so, &fromsa, uiop,
			(struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
			&mp->msg_flags);
	}
	AUDIT_ARG(sockaddr, p, fromsa);
	if (error) {
		if (uio_resid(uiop) != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
#if KTRACE
	if (ktruio != NULL) {
		if (error == 0) {
			uio_setresid(ktruio, len - uio_resid(uiop));
			ktrgenio(p->p_tracep, s, UIO_WRITE, ktruio, error);
		}
		uio_free(ktruio);
	}
#endif
	if (error)
		goto out;
	*retval = len - uio_resid(uiop);
	if (mp->msg_name) {
		len = mp->msg_namelen;
		if (len <= 0 || fromsa == 0)
			len = 0;
		else {
#ifndef MIN
#define MIN(a,b) ((a)>(b)?(b):(a))
#endif
			/* save sa_len before it is destroyed by MSG_COMPAT */
			len = MIN(len, fromsa->sa_len);
#if COMPAT_43_SOCKET
			if (mp->msg_flags & MSG_COMPAT)
				((struct osockaddr *)fromsa)->sa_family =
				    fromsa->sa_family;
#endif
			error = copyout(fromsa, mp->msg_name, (unsigned)len);
			if (error)
				goto out;
		}
		mp->msg_namelen = len;
		if (namelenp &&
		    (error = copyout((caddr_t)&len, namelenp, sizeof (int)))) {
#if COMPAT_43_SOCKET
			if (mp->msg_flags & MSG_COMPAT)
				error = 0;	/* old recvfrom didn't check */
			else
#endif
			goto out;
		}
	}
	if (mp->msg_control) {
#if COMPAT_43_SOCKET
		/*
		 * We assume that old recvmsg calls won't receive access
		 * rights and other control info, esp. as control info
		 * is always optional and those options didn't exist in 4.3.
		 * If we receive rights, trim the cmsghdr; anything else
		 * is tossed.
		 */
		if (control && mp->msg_flags & MSG_COMPAT) {
			if (mtod(control, struct cmsghdr *)->cmsg_level !=
			    SOL_SOCKET ||
			    mtod(control, struct cmsghdr *)->cmsg_type !=
			    SCM_RIGHTS) {
				mp->msg_controllen = 0;
				goto out;
			}
			control->m_len -= sizeof (struct cmsghdr);
			control->m_data += sizeof (struct cmsghdr);
		}
#endif
		len = mp->msg_controllen;
		m = control;
		mp->msg_controllen = 0;
		ctlbuf = mp->msg_control;

		while (m && len > 0) {
			unsigned int tocopy;

			if (len >= m->m_len) 
				tocopy = m->m_len;
			else {
				mp->msg_flags |= MSG_CTRUNC;
				tocopy = len;
			}
		
			error = copyout((caddr_t)mtod(m, caddr_t), ctlbuf, tocopy);
			if (error)
				goto out;

			ctlbuf += tocopy;
			len -= tocopy;
			m = m->m_next;
		}
		mp->msg_controllen = ctlbuf - mp->msg_control;
	}
out:
	if (fromsa)
		FREE(fromsa, M_SONAME);
	if (control)
		m_freem(control);
	KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, error,0,0,0,0);
out1:
	fp_drop(p, s, fp, 0);
	return (error);
}


int
recvfrom(p, uap, retval)
	struct proc *p;
	register struct recvfrom_args /* {
		int	s;
		caddr_t	buf;
		size_t	len;
		int	flags;
		caddr_t	from;
		int	*fromlenaddr;
	} */ *uap;
	register_t *retval;
{
	struct user_msghdr msg;
	int error;
	uio_t auio = NULL;

	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_START, 0,0,0,0,0);
	AUDIT_ARG(fd, uap->s);

	if (uap->fromlenaddr) {
		error = copyin(uap->fromlenaddr,
		    (caddr_t)&msg.msg_namelen, sizeof (msg.msg_namelen));
		if (error)
			return (error);
	} else
		msg.msg_namelen = 0;
	msg.msg_name = uap->from;
	auio = uio_create(1, 0,
				  (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
				  UIO_READ);
	if (auio == NULL) {
		return (ENOMEM);
	}
	
	uio_addiov(auio, uap->buf, uap->len);
	/* no need to set up msg_iov.  recvit uses uio_t we send it */
	msg.msg_iov = 0;
	msg.msg_iovlen = 0;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = uap->flags;
	error = recvit(p, uap->s, &msg, auio, uap->fromlenaddr, retval);
	if (auio != NULL) {
		uio_free(auio);
	}
	
#if HACK_FOR_4056224
	/* 
	 * Radar 4056224 
	 * Temporary workaround to let send() and recv() work over a pipe for binary compatibility
	 * This will be removed in the release following Tiger
	 */
	if (error == ENOTSOCK && proc_is64bit(p) == 0) {
		struct fileproc *fp;
		
        if (fp_lookup(p, uap->s, &fp, 0) == 0) {
			(void) fp_drop(p, uap->s, fp,0);
			
			if (fp->f_type == DTYPE_PIPE) {
				struct read_args read_uap;
				user_ssize_t read_retval;
				
				if (p->p_pid > last_pid_4056224) {
					last_pid_4056224 = p->p_pid;

					printf("%s[%d] uses send/recv on a pipe\n", 
						p->p_comm, p->p_pid);
				}
				
				bzero(&read_uap, sizeof(struct read_args));
				read_uap.fd = uap->s;
				read_uap.cbuf = uap->buf;
				read_uap.nbyte = uap->len;
	
				error = read(p, &read_uap, &read_retval);
				*retval = (int)read_retval;
			}
		}
	}
#endif /* HACK_FOR_4056224 */

	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_END, error,0,0,0,0);
	
	return (error);
}

#if COMPAT_43_SOCKET
int
orecvfrom(struct proc *p, struct recvfrom_args *uap, register_t *retval)
{

	uap->flags |= MSG_COMPAT;
	return (recvfrom(p, uap, retval));
}
#endif


#if COMPAT_43_SOCKET
int
orecv(__unused struct proc *p, __unused struct orecv_args	*uap, 
		__unused register_t *retval)
{
	/* these are no longer supported and in fact 
	 * there is no way to call it directly.
	 * LP64todo - remove this once we're sure there are no clients 
	 */

	return (ENOTSUP);
}

/*
 * Old recvmsg.  This code takes advantage of the fact that the old msghdr
 * overlays the new one, missing only the flags, and with the (old) access
 * rights where the control fields are now.
 */
int
orecvmsg(__unused struct proc *p, __unused struct orecvmsg_args *uap, 
		__unused register_t *retval)
{
	/* these are no longer supported and in fact 
	 * there is no way to call it directly.
	 * LP64todo - remove this once we're sure there are no clients 
	 */

	return (ENOTSUP);

}
#endif

int
recvmsg(p, uap, retval)
	struct proc *p;
	struct recvmsg_args *uap;
	register_t *retval;
{
	struct msghdr msg;
	struct user_msghdr user_msg;
	caddr_t msghdrp;
	int	size_of_msghdr;
	user_addr_t uiov;
	register int error;
	int size_of_iovec;
	uio_t auio = NULL;
	struct user_iovec *iovp;

	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_START, 0,0,0,0,0);
	AUDIT_ARG(fd, uap->s);
	if (IS_64BIT_PROCESS(p)) {
		msghdrp = (caddr_t) &user_msg;
		size_of_msghdr = sizeof(user_msg);
		size_of_iovec = sizeof(struct user_iovec);
	}
	else {
		msghdrp = (caddr_t) &msg;
		size_of_msghdr = sizeof(msg);
		size_of_iovec = sizeof(struct iovec);
	}
	error = copyin(uap->msg, msghdrp, size_of_msghdr);
	if (error)
	{
	    	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error,0,0,0,0);
		return (error);
	}

	/* only need to copy if user process is not 64-bit */
	if (!IS_64BIT_PROCESS(p)) {
		user_msg.msg_flags = msg.msg_flags;
		user_msg.msg_controllen = msg.msg_controllen;
		user_msg.msg_control = CAST_USER_ADDR_T(msg.msg_control);
		user_msg.msg_iovlen = msg.msg_iovlen;
		user_msg.msg_iov = CAST_USER_ADDR_T(msg.msg_iov);
		user_msg.msg_namelen = msg.msg_namelen;
		user_msg.msg_name = CAST_USER_ADDR_T(msg.msg_name);
	}

	if (user_msg.msg_iovlen <= 0 || user_msg.msg_iovlen > UIO_MAXIOV) {
		KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, EMSGSIZE,0,0,0,0);
		return (EMSGSIZE);
	}

#if COMPAT_43_SOCKET
	user_msg.msg_flags = uap->flags &~ MSG_COMPAT;
#else
	user_msg.msg_flags = uap->flags;
#endif

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(user_msg.msg_iovlen, 0,
				  (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
				  UIO_READ);
	if (auio == NULL) {
		error = ENOMEM;
		goto done;
	}

	/* get location of iovecs within the uio.  then copyin the iovecs from
	 * user space.
	 */
	iovp = uio_iovsaddr(auio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto done;
	}
	uiov = user_msg.msg_iov;
	user_msg.msg_iov = CAST_USER_ADDR_T(iovp);
	error = copyin(uiov, (caddr_t)iovp, (user_msg.msg_iovlen * size_of_iovec));
	if (error)
		goto done;

	/* finish setup of uio_t */ 
	uio_calculateresid(auio);
		
	error = recvit(p, uap->s, &user_msg, auio, 0, retval);
	if (!error) {
		user_msg.msg_iov = uiov;
		/* only need to copy if user process is not 64-bit */
		if (!IS_64BIT_PROCESS(p)) {
			// LP64todo - do all these change?  if not, then no need to copy all of them!
			msg.msg_flags = user_msg.msg_flags;
			msg.msg_controllen = user_msg.msg_controllen;
			msg.msg_control = CAST_DOWN(caddr_t, user_msg.msg_control);
			msg.msg_iovlen = user_msg.msg_iovlen;
			msg.msg_iov = (struct iovec *) CAST_DOWN(caddr_t, user_msg.msg_iov);
			msg.msg_namelen = user_msg.msg_namelen;
			msg.msg_name = CAST_DOWN(caddr_t, user_msg.msg_name);
		}
		error = copyout(msghdrp, uap->msg, size_of_msghdr);
	}
done:
	if (auio != NULL) {
		uio_free(auio);
	}
	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error,0,0,0,0);
	return (error);
}

/* ARGSUSED */
int
shutdown(__unused struct proc *p, struct shutdown_args *uap, __unused register_t *retval)
{
	struct socket * so;
	int error;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	error =  soshutdown((struct socket *)so, uap->how);
out:
	file_drop(uap->s);
	return(error);
}





/* ARGSUSED */
int
setsockopt(struct proc *p, struct setsockopt_args *uap, __unused register_t *retval)
{
	struct socket * so;
	struct sockopt sopt;
	int error;

	AUDIT_ARG(fd, uap->s);
	if (uap->val == 0 && uap->valsize != 0)
		return (EFAULT);
	if (uap->valsize < 0)
		return (EINVAL);

	error = file_socket(uap->s, &so);
	if (error)
		return (error);

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = uap->level;
	sopt.sopt_name = uap->name;
	sopt.sopt_val = uap->val;
	sopt.sopt_valsize = uap->valsize;
	sopt.sopt_p = p;

	if (so == NULL) {
		error = EINVAL;
		goto out;
	}
	error = sosetopt(so, &sopt);
out:
	file_drop(uap->s);
	return(error);
}



int
getsockopt(struct proc *p, struct getsockopt_args  *uap, __unused register_t *retval)
{
	int		error;
	socklen_t	valsize;
	struct sockopt	sopt;
	struct socket *	so;

	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	if (uap->val) {
		error = copyin(uap->avalsize, (caddr_t)&valsize, sizeof (valsize));
		if (error)
			goto out;
		if (valsize < 0) {
			error = EINVAL;
			goto out;
		}
	} else
		valsize = 0;

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = uap->level;
	sopt.sopt_name = uap->name;
	sopt.sopt_val = uap->val;
	sopt.sopt_valsize = (size_t)valsize; /* checked non-negative above */
	sopt.sopt_p = p;

	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	error = sogetopt((struct socket *)so, &sopt);
	if (error == 0) {
		valsize = sopt.sopt_valsize;
		error = copyout((caddr_t)&valsize, uap->avalsize, sizeof (valsize));
	}
out:
	file_drop(uap->s);
	return (error);
}


/*
 * Get socket name.
 */
/* ARGSUSED */
static int
getsockname1(__unused struct proc *p, struct getsockname_args *uap, __unused register_t *retval,
	int compat)
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	int error;

	error = file_socket(uap->fdes, &so);
	if (error)
		return (error);
	error = copyin(uap->alen, (caddr_t)&len, sizeof(socklen_t));
	if (error)
		goto out;
	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	sa = 0;
	socket_lock(so, 1);
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	if (error == 0)
	{
		struct socket_filter_entry *filter;
		int	filtered = 0;
		for (filter = so->so_filt; filter && error == 0;
			 filter = filter->sfe_next_onsocket) {
			if (filter->sfe_filter->sf_filter.sf_getsockname) {
				if (!filtered) {
					filtered = 1;
					sflt_use(so);
					socket_unlock(so, 0);
				}
				error = filter->sfe_filter->sf_filter.sf_getsockname(filter->sfe_cookie,
							so, &sa);
			}
		}
		
		if (error == EJUSTRETURN)
			error = 0;
		
		if (filtered) {
			socket_lock(so, 0);
			sflt_unuse(so);
		}
	}
	socket_unlock(so, 1);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}

	len = MIN(len, sa->sa_len);
#if COMPAT_43_SOCKET
	if (compat)
		((struct osockaddr *)sa)->sa_family = sa->sa_family;
#endif
	error = copyout((caddr_t)sa, uap->asa, len);
	if (error == 0)
gotnothing:
		error = copyout((caddr_t)&len, uap->alen, sizeof(socklen_t));
bad:
	if (sa)
		FREE(sa, M_SONAME);
out:
	file_drop(uap->fdes);
	return (error);
}

int
getsockname(struct proc *p, struct getsockname_args *uap, register_t *retval)
{
	return (getsockname1(p, uap, retval, 0));
}

#if COMPAT_43_SOCKET
int
ogetsockname(struct proc *p, struct getsockname_args *uap, register_t *retval)
{
	return (getsockname1(p, uap, retval, 1));
}
#endif /* COMPAT_43_SOCKET */

/*
 * Get name of peer for connected socket.
 */
/* ARGSUSED */
int
getpeername1(__unused struct proc *p, struct getpeername_args *uap, __unused register_t *retval,
	int compat)
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	int error;

	error = file_socket(uap->fdes, &so);
	if (error)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}

	socket_lock(so, 1);

	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING)) == 0) {
		socket_unlock(so, 1);
		error = ENOTCONN;
		goto out;
	}
	error = copyin(uap->alen, (caddr_t)&len, sizeof(socklen_t));
	if (error) {
		socket_unlock(so, 1);
		goto out;
	}
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
	if (error == 0)
	{
		struct socket_filter_entry *filter;
		int	filtered = 0;
		for (filter = so->so_filt; filter && error == 0;
			 filter = filter->sfe_next_onsocket) {
			if (filter->sfe_filter->sf_filter.sf_getpeername) {
				if (!filtered) {
					filtered = 1;
					sflt_use(so);
					socket_unlock(so, 0);
				}
				error = filter->sfe_filter->sf_filter.sf_getpeername(filter->sfe_cookie,
							so, &sa);
			}
		}
		
		if (error == EJUSTRETURN)
			error = 0;
		
		if (filtered) {
			socket_lock(so, 0);
			sflt_unuse(so);
		}
	}
	socket_unlock(so, 1);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}
	len = MIN(len, sa->sa_len);
#if COMPAT_43_SOCKET
	if (compat)
		((struct osockaddr *)sa)->sa_family =
		    sa->sa_family;
#endif
	error = copyout(sa, uap->asa, len);
	if (error)
		goto bad;
gotnothing:
	error = copyout((caddr_t)&len, uap->alen, sizeof(socklen_t));
bad:
	if (sa) FREE(sa, M_SONAME);
out:
	file_drop(uap->fdes);
	return (error);
}

int
getpeername(struct proc *p, struct getpeername_args *uap, register_t *retval)
{

	return (getpeername1(p, uap, retval, 0));
}

#if COMPAT_43_SOCKET
int
ogetpeername(struct proc *p, struct getpeername_args *uap, register_t *retval)
{

	return (getpeername1(p, uap, retval, 1));
}
#endif /* COMPAT_43_SOCKET */

int
sockargs(mp, data, buflen, type)
	struct mbuf **mp;
	user_addr_t data;
	int buflen, type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
#if COMPAT_43_SOCKET
		if (type == MT_SONAME && (u_int)buflen <= 112)
			buflen = MLEN;		/* unix domain compat. hack */
		else
#endif
		if ((u_int)buflen > MCLBYTES)
			return (EINVAL);
	}
	m = m_get(M_WAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	if ((u_int)buflen > MLEN) {
		MCLGET(m, M_WAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return ENOBUFS;
		}
	}
	m->m_len = buflen;
	error = copyin(data, mtod(m, caddr_t), (u_int)buflen);
	if (error)
		(void) m_free(m);
	else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);

#if COMPAT_43_SOCKET && BYTE_ORDER != BIG_ENDIAN
			if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
				sa->sa_family = sa->sa_len;
#endif
			sa->sa_len = buflen;
		}
	}
	return (error);
}

/*
 * Given a user_addr_t of length len, allocate and fill out a *sa.
 */
int
getsockaddr(struct sockaddr **namp, user_addr_t uaddr, size_t len)
{
	struct sockaddr *sa;
	int error;

	if (len > SOCK_MAXADDRLEN)
		return ENAMETOOLONG;

	if (len == 0)
	     return EINVAL;

	MALLOC(sa, struct sockaddr *, len, M_SONAME, M_WAITOK);
	if (sa == NULL) {
		return ENOMEM;
	}
	error = copyin(uaddr, (caddr_t)sa, len);
	if (error) {
		FREE(sa, M_SONAME);
	} else {
#if COMPAT_43_SOCKET && BYTE_ORDER != BIG_ENDIAN
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = len;
		*namp = sa;
	}
	return error;
}


#if SENDFILE
/*
 * Allocate a pool of sf_bufs (sendfile(2) or "super-fast" if you prefer. :-))
 * XXX - The sf_buf functions are currently private to sendfile(2), so have
 * been made static, but may be useful in the future for doing zero-copy in
 * other parts of the networking code. 
 */
static void
sf_buf_init(void *arg)
{
	int i;

	SLIST_INIT(&sf_freelist);
	kmem_alloc_pageable(kernel_map, &sf_base, nsfbufs * PAGE_SIZE);
	MALLOC(sf_bufs, struct sf_buf *, nsfbufs * sizeof(struct sf_buf), M_TEMP, M_NOWAIT|M_ZERO);
	if (sf_bufs == NULL)
		return;		/* XXX silently fail leaving sf_bufs NULL */

	for (i = 0; i < nsfbufs; i++) {
		sf_bufs[i].kva = sf_base + i * PAGE_SIZE;
		SLIST_INSERT_HEAD(&sf_freelist, &sf_bufs[i], free_list);
	}
}

/*
 * Get an sf_buf from the freelist. Will block if none are available.
 */
static struct sf_buf *
sf_buf_alloc()
{
	struct sf_buf *sf;

	while ((sf = SLIST_FIRST(&sf_freelist)) == NULL) {
		sf_buf_alloc_want = 1;
		tsleep(&sf_freelist, PVM, "sfbufa", 0);
	}
	SLIST_REMOVE_HEAD(&sf_freelist, free_list);
	sf->refcnt = 1;
	return (sf);
}

#define dtosf(x)	(&sf_bufs[((uintptr_t)(x) - (uintptr_t)sf_base) >> PAGE_SHIFT])
static void
sf_buf_ref(caddr_t addr, u_int size)
{
	struct sf_buf *sf;

	sf = dtosf(addr);
	if (sf->refcnt == 0)
		panic("sf_buf_ref: referencing a free sf_buf");
	sf->refcnt++;
}

/*
 * Lose a reference to an sf_buf. When none left, detach mapped page
 * and release resources back to the system.
 *
 * Must be called at splimp.
 */
static void
sf_buf_free(caddr_t addr, u_int size)
{
	struct sf_buf *sf;
	struct vm_page *m;

	sf = dtosf(addr);
	if (sf->refcnt == 0)
		panic("sf_buf_free: freeing free sf_buf");
	sf->refcnt--;
	if (sf->refcnt == 0) {
		pmap_qremove((vm_offset_t)addr, 1);
		m = sf->m;
		vm_page_unwire(m, 0);
		/*
		 * Check for the object going away on us. This can
		 * happen since we don't hold a reference to it.
		 * If so, we're responsible for freeing the page.
		 */
		if (m->wire_count == 0 && m->object == NULL)
			vm_page_lock_queues();
			vm_page_free(m);
			vm_page_unlock_queues();
		sf->m = NULL;
		SLIST_INSERT_HEAD(&sf_freelist, sf, free_list);
		if (sf_buf_alloc_want) {
			sf_buf_alloc_want = 0;
			wakeup(&sf_freelist);
		}
	}
}

/*
 * sendfile(2).
 * int sendfile(int fd, int s, off_t offset, size_t nbytes,
 *	 struct sf_hdtr *hdtr, off_t *sbytes, int flags)
 *
 * Send a file specified by 'fd' and starting at 'offset' to a socket
 * specified by 's'. Send only 'nbytes' of the file or until EOF if
 * nbytes == 0. Optionally add a header and/or trailer to the socket
 * output. If specified, write the total number of bytes sent into *sbytes.
 */
int
sendfile(struct proc *p, struct sendfile_args *uap)
{
	struct fileproc *fp;
	struct vnode *vp;
	struct vm_object *obj;
	struct socket *so;
	struct mbuf *m;
	struct sf_buf *sf;
	struct vm_page *pg;
	struct writev_args nuap;
	struct sf_hdtr hdtr;
	off_t off, xfsize, sbytes = 0;
	int error = 0, s;

	if (sf_bufs == NULL) {
		/* Fail if initialization failed */
		return ENOSYS;
	}

	/*
	 * Do argument checking. Must be a regular file in, stream
	 * type and connected socket out, positive offset.
	 */
	if (error = fp_getfvp(p, uap->fd, &fp, &vp))
		goto done;
	if (fp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto done1;
	}
	obj = vp->v_object;
	if (vp->v_type != VREG || obj == NULL) {
		error = EINVAL;
		goto done1;
	}
	error = file_socket(uap->s, &so);
	if (error)
		goto done1;
	if (so == NULL) {
		error = EBADF;
		goto done2;
	}

	socket_lock(so, 1);

	if (so->so_type != SOCK_STREAM) {
		error = EINVAL;
		goto done3;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto done3;
	}
	if (uap->offset < 0) {
		error = EINVAL;
		goto done3;
	}

	/*
	 * If specified, get the pointer to the sf_hdtr struct for
	 * any headers/trailers.
	 */
	if (uap->hdtr != NULL) {
		error = copyin(CAST_USER_ADDR_T(uap->hdtr), &hdtr, sizeof(hdtr));
		if (error)
			goto done3;
		/*
		 * Send any headers. Wimp out and use writev(2).
		 */
		if (hdtr.headers != NULL) {
			nuap.fd = uap->s;
			nuap.iovp = hdtr.headers;
			nuap.iovcnt = hdtr.hdr_cnt;
			error = writev(p, &nuap);
			if (error)
				goto done3;
			sbytes += p->p_retval[0];
		}
	}

	/*
	 * Protect against multiple writers to the socket.
	 */
	(void) sblock(&so->so_snd, M_WAIT);

	/*
	 * Loop through the pages in the file, starting with the requested
	 * offset. Get a file page (do I/O if necessary), map the file page
	 * into an sf_buf, attach an mbuf header to the sf_buf, and queue
	 * it on the socket.
	 */
	for (off = uap->offset; ; off += xfsize, sbytes += xfsize) {
		vm_object_offset_t pindex;
		vm_object_offset_t pgoff;

		pindex = OFF_TO_IDX(off);
retry_lookup:
		/*
		 * Calculate the amount to transfer. Not to exceed a page,
		 * the EOF, or the passed in nbytes.
		 */
		xfsize = obj->un_pager.vnp.vnp_size - off;
		if (xfsize > PAGE_SIZE_64)
			xfsize = PAGE_SIZE;
		pgoff = (vm_object_offset_t)(off & PAGE_MASK_64);
		if (PAGE_SIZE - pgoff < xfsize)
			xfsize = PAGE_SIZE_64 - pgoff;
		if (uap->nbytes && xfsize > (uap->nbytes - sbytes))
			xfsize = uap->nbytes - sbytes;
		if (xfsize <= 0)
			break;
		/*
		 * Optimize the non-blocking case by looking at the socket space
		 * before going to the extra work of constituting the sf_buf.
		 */
		if ((so->so_state & SS_NBIO) && sbspace(&so->so_snd) <= 0) {
			if (so->so_state & SS_CANTSENDMORE)
				error = EPIPE;
			else
				error = EAGAIN;
			sbunlock(&so->so_snd, 0); /* will release lock */
			goto done2;
		}
		/*
		 * Attempt to look up the page. If the page doesn't exist or the
		 * part we're interested in isn't valid, then read it from disk.
		 * If some other part of the kernel has this page (i.e. it's busy),
		 * then disk I/O may be occuring on it, so wait and retry.
		 */
		pg = vm_page_lookup(obj, pindex);
		if (pg == NULL || (!(pg->flags & PG_BUSY) && !pg->busy &&
		    !vm_page_is_valid(pg, pgoff, xfsize))) {
			struct uio auio;
			struct iovec aiov;
			int bsize;

			if (pg == NULL) {
				pg = vm_page_alloc(obj, pindex, VM_ALLOC_NORMAL);
				if (pg == NULL) {
					VM_WAIT;
					goto retry_lookup;
				}
				/*
				 * don't just clear PG_BUSY manually -
				 * vm_page_alloc() should be considered opaque,
				 * use the VM routine provided to clear
				 * PG_BUSY.
				 */
				vm_page_wakeup(pg);

			}
			/*
			 * Ensure that our page is still around when the I/O completes.
			 */
			vm_page_io_start(pg);
			vm_page_wire(pg);
			/*
			 * Get the page from backing store.
			 */
			bsize = vp->v_mount->mnt_vfsstat.f_iosize;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			aiov.iov_base = 0;
			aiov.iov_len = MAXBSIZE;
			auio.uio_offset = trunc_page(off);
			auio.uio_segflg = UIO_NOCOPY;
			auio.uio_rw = UIO_READ;
			uio_setresid(&auio, MAXBSIZE);
			error = VOP_READ(vp, &auio, IO_VMIO | ((MAXBSIZE / bsize) << 16),
			        p->p_ucred);
			vm_page_flag_clear(pg, PG_ZERO);
			vm_page_io_finish(pg);
			if (error) {
				vm_page_unwire(pg, 0);
				/*
				 * See if anyone else might know about this page.
				 * If not and it is not valid, then free it.
				 */
				if (pg->wire_count == 0 && pg->valid == 0 &&
				    pg->busy == 0 && !(pg->flags & PG_BUSY) &&
				    pg->hold_count == 0)
					vm_page_lock_queues();
					vm_page_free(pg);
					vm_page_unlock_queues();
				sbunlock(&so->so_snd, 0); /* will release socket lock */
				goto done2;
			}
		} else {
			if ((pg->flags & PG_BUSY) || pg->busy)  {
				s = splvm();
				if ((pg->flags & PG_BUSY) || pg->busy) {
					/*
					 * Page is busy. Wait and retry.
					 */
					vm_page_flag_set(pg, PG_WANTED);
					tsleep(pg, PVM, "sfpbsy", 0);
					goto retry_lookup;
				}
			}
			/*
			 * Protect from having the page ripped out from beneath us.
			 */
			vm_page_wire(pg);
		}
		/*
		 * Allocate a kernel virtual page and insert the physical page
		 * into it.
		 */
		sf = sf_buf_alloc();
		sf->m = pg;
		pmap_qenter(sf->kva, &pg, 1);
		/*
		 * Get an mbuf header and set it up as having external storage.
		 */
		MGETHDR(m, M_WAIT, MT_DATA);
		if (m == NULL) {
			error = ENOBUFS;
			sbunlock(&so->so_snd, 0); /* will release socket lock */
			goto done2;
		}
		m->m_ext.ext_free = sf_buf_free;
		m->m_ext.ext_ref = sf_buf_ref;
		m->m_ext.ext_buf = (void *)sf->kva;
		m->m_ext.ext_size = PAGE_SIZE;
		m->m_data = (char *) sf->kva + pgoff;
		m->m_flags |= M_EXT;
		m->m_pkthdr.len = m->m_len = xfsize;
		/*
		 * Add the buffer to the socket buffer chain.
		 */
retry_space:
		/*
		 * Make sure that the socket is still able to take more data.
		 * CANTSENDMORE being true usually means that the connection
		 * was closed. so_error is true when an error was sensed after
		 * a previous send.
		 * The state is checked after the page mapping and buffer
		 * allocation above since those operations may block and make
		 * any socket checks stale. From this point forward, nothing
		 * blocks before the pru_send (or more accurately, any blocking
		 * results in a loop back to here to re-check).
		 */
		if ((so->so_state & SS_CANTSENDMORE) || so->so_error) {
			if (so->so_state & SS_CANTSENDMORE) {
				error = EPIPE;
			} else {
				error = so->so_error;
				so->so_error = 0;
			}
			m_freem(m);
			sbunlock(&so->so_snd, 0); /* will release socket lock */
			goto done2;
		}
		/*
		 * Wait for socket space to become available. We do this just
		 * after checking the connection state above in order to avoid
		 * a race condition with sbwait().
		 */
		if (sbspace(&so->so_snd) < so->so_snd.sb_lowat) {
			if (so->so_state & SS_NBIO) {
				m_freem(m);
				sbunlock(&so->so_snd, 0); /* will release socket lock */
				error = EAGAIN;
				goto done2;
			}
			error = sbwait(&so->so_snd);
			/*
			 * An error from sbwait usually indicates that we've
			 * been interrupted by a signal. If we've sent anything
			 * then return bytes sent, otherwise return the error.
			 */
			if (error) {
				m_freem(m);
				sbunlock(&so->so_snd, 0);
				goto done2;
			}
			goto retry_space;
		}
		error = (*so->so_proto->pr_usrreqs->pru_send)(so, 0, m, 0, 0, p);
		splx(s);
		if (error) {
			sbunlock(&so->so_snd, 0); /* will release socket lock */
			goto done2;
		}
	}
	sbunlock(&so->so_snd, 0); /* will release socket lock */

	/*
	 * Send trailers. Wimp out and use writev(2).
	 */
	if (uap->hdtr != NULL && hdtr.trailers != NULL) {
			nuap.fd = uap->s;
			nuap.iovp = hdtr.trailers;
			nuap.iovcnt = hdtr.trl_cnt;
			error = writev(p, &nuap);
			if (error)
				goto done2;
			sbytes += p->p_retval[0];
	}
done2:
	file_drop(uap->s);
done1:
	file_drop(uap->fd);
done:
	if (uap->sbytes != NULL) {
		/* XXX this appears bogus for some early failure conditions */
		copyout(&sbytes, CAST_USER_ADDR_T(uap->sbytes), sizeof(off_t));
	}
	return (error);
done3:
	socket_unlock(so, 1);
	goto done2;
}

#endif
