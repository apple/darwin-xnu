/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/kernel.h>

#include <sys/kdebug.h>

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

struct getsockname_args  {
    int	fdes;
    caddr_t	asa;
    int	*alen;
};

struct getsockopt_args  {
    int	s;
    int	level;
    int	name;
    caddr_t	val;
    int	*avalsize;
} ;

struct accept_args {
	int	s;
	caddr_t	name;
	int	*anamelen;
};

struct getpeername_args {
	int	fdes;
	caddr_t	asa;
	int	*alen;
};


/* ARGSUSED */

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

static int sendit __P((struct proc *p, int s, struct msghdr *mp, int flags, register_t *retval));
static int recvit __P((struct proc *p, int s, struct msghdr *mp,
		       caddr_t namelenp, register_t *retval));
  
static int accept1 __P((struct proc *p, struct accept_args *uap, register_t *retval, int compat));
static int getsockname1 __P((struct proc *p, struct getsockname_args *uap,
			     register_t *retval, int compat));
static int getpeername1 __P((struct proc *p, struct getpeername_args *uap,
			     register_t *retval, int compat));

/*
 * System call interface to the socket abstraction.
 */
#if COMPAT_43 || defined(COMPAT_SUNOS)
#define COMPAT_OLDSOCK
#endif

extern	struct fileops socketops;

struct socket_args {
	int	domain;
	int	type;
	int	protocol;
};
int
socket(p, uap, retval)
	struct proc *p;
	register struct socket_args *uap;
	register_t *retval;
{
	struct filedesc *fdp = p->p_fd;
	struct socket *so;
	struct file *fp;
	int fd, error;

	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	error = falloc(p, &fp, &fd);
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);

	if (error)
		return (error);
	fp->f_flag = FREAD|FWRITE;
	fp->f_type = DTYPE_SOCKET;
	fp->f_ops = &socketops;
	if (error = socreate(uap->domain, &so, uap->type,
	    uap->protocol)) {
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		fdrelse(p, fd);
		ffree(fp);
		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	} else {
		fp->f_data = (caddr_t)so;
		*fdflags(p, fd) &= ~UF_RESERVED;
		*retval = fd;
	}
	return (error);
}

struct bind_args {
	int	s;
	caddr_t	name;
	int	namelen;
};

/* ARGSUSED */
int
bind(p, uap, retval)
	struct proc *p;
	register struct bind_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct sockaddr *sa;
	int error;

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error)
		return (error);
	error = sobind((struct socket *)fp->f_data, sa);
	FREE(sa, M_SONAME);
	return (error);
}

struct listen_args {
	int	s;
	int	backlog;
};



int
listen(p, uap, retval)
	struct proc *p;
	register struct listen_args *uap;
	register_t *retval;
{
	struct file *fp;
	int error;

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	return (solisten((struct socket *)fp->f_data, uap->backlog));
}

#ifndef COMPAT_OLDSOCK
#define	accept1	accept
#endif



int
accept1(p, uap, retval, compat)
	struct proc *p;
	register struct accept_args *uap;
	register_t *retval;
	int compat;
{
	struct file *fp;
	struct sockaddr *sa;
	u_int  namelen;
	int error, s;
	struct socket *head, *so;
	int fd;
	short fflag;		/* type must match fp->f_flag */
	int tmpfd;

	if (uap->name) {
		error = copyin((caddr_t)uap->anamelen, (caddr_t)&namelen,
			sizeof (namelen));
		if(error)
			return (error);
	}
	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	s = splnet();
	head = (struct socket *)fp->f_data;
	if ((head->so_options & SO_ACCEPTCONN) == 0) {
		splx(s);
		return (EINVAL);
	}
	if ((head->so_state & SS_NBIO) && head->so_comp.tqh_first == NULL) {
		splx(s);
		return (EWOULDBLOCK);
	}
        while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_state & SS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		error = tsleep((caddr_t)&head->so_timeo, PSOCK | PCATCH,
		    "accept", 0);
		if (error) {
			splx(s);
			return (error);
		}
	}
	if (head->so_error) {
		error = head->so_error;
		head->so_error = 0;
		splx(s);
		return (error);
	}


	/*
	 * At this point we know that there is at least one connection
	 * ready to be accepted. Remove it from the queue prior to
	 * allocating the file descriptor for it since falloc() may
	 * block allowing another process to accept the connection
	 * instead.
	 */
	so = TAILQ_FIRST(&head->so_comp);
	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;

	fflag = fp->f_flag;
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	error = falloc(p, &fp, &fd);
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	if (error) {
		/*
		 * Probably ran out of file descriptors. Put the
		 * unaccepted connection back onto the queue and
		 * do another wakeup so some other process might
		 * have a chance at it.
		 */
		TAILQ_INSERT_HEAD(&head->so_comp, so, so_list);
		head->so_qlen++;
		wakeup_one(&head->so_timeo);
		splx(s);
		return (error);
	} else {
		*fdflags(p, fd) &= ~UF_RESERVED;
		*retval = fd;
	}

	so->so_state &= ~SS_COMP;
	so->so_head = NULL;
	fp->f_type = DTYPE_SOCKET;
	fp->f_flag = fflag;
	fp->f_ops = &socketops;
	fp->f_data = (caddr_t)so;
	sa = 0;
	(void) soaccept(so, &sa);
	if (sa == 0) {
		namelen = 0;
		if (uap->name)
			goto gotnoname;
		return 0;
	}
	if (uap->name) {
		/* check sa_len before it is destroyed */
		if (namelen > sa->sa_len)
			namelen = sa->sa_len;
#ifdef COMPAT_OLDSOCK
		if (compat)
			((struct osockaddr *)sa)->sa_family =
			    sa->sa_family;
#endif
		error = copyout(sa, (caddr_t)uap->name, (u_int)namelen);
		if (!error)
gotnoname:
			error = copyout((caddr_t)&namelen,
			    (caddr_t)uap->anamelen, sizeof (*uap->anamelen));
	}
	FREE(sa, M_SONAME);
	splx(s);
	return (error);
}

int
accept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	register_t *retval;
{

	return (accept1(p, uap, retval, 0));
}

#ifdef COMPAT_OLDSOCK
int
oaccept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	register_t *retval;
{

	return (accept1(p, uap, retval, 1));
}
#endif /* COMPAT_OLDSOCK */

struct connect_args {
	int s;
	caddr_t name;
	int	namelen;
};
/* ARGSUSED */
int
connect(p, uap, retval)
	struct proc *p;
	register struct connect_args *uap;
	register_t *retval;
{
	struct file *fp;
	register struct socket *so;
	struct sockaddr *sa;
	int error, s;

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	so = (struct socket *)fp->f_data;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING))
		return (EALREADY);
	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error)
		return (error);
	error = soconnect(so, sa);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		FREE(sa, M_SONAME);
		return (EINPROGRESS);
	}
	s = splnet();
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = tsleep((caddr_t)&so->so_timeo, PSOCK | PCATCH,
		    "connec", 0);
		if (error)
			break;
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	splx(s);
bad:
	so->so_state &= ~SS_ISCONNECTING;
	FREE(sa, M_SONAME);
	if (error == ERESTART)
		error = EINTR;
	return (error);
}

struct socketpair_args {
	int	domain;
	int	type;
	int	protocol;
	int	*rsv;
};
int
socketpair(p, uap, retval)
	struct proc *p;
	register struct socketpair_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	struct file *fp1, *fp2;
	struct socket *so1, *so2;
	int fd, error, sv[2];

	error = socreate(uap->domain, &so1, uap->type, uap->protocol);
	if (error)
		return (error);
	error = socreate(uap->domain, &so2, uap->type, uap->protocol);
	if (error)
		goto free1;
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	error = falloc(p, &fp1, &fd);
	if (error)
		goto free2;
	sv[0] = fd;
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_type = DTYPE_SOCKET;
	fp1->f_ops = &socketops;
	fp1->f_data = (caddr_t)so1;
	error = falloc(p, &fp2, &fd);
	if (error)
		goto free3;
	fp2->f_flag = FREAD|FWRITE;
	fp2->f_type = DTYPE_SOCKET;
	fp2->f_ops = &socketops;
	fp2->f_data = (caddr_t)so2;
	sv[1] = fd;
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	error = soconnect2(so1, so2);
	if (error) {
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		goto free4;
	}

	if (uap->type == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		 error = soconnect2(so2, so1);
		 if (error) {
			 thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			 goto free4;
		 }
	}
	*fdflags(p, sv[0]) &= ~UF_RESERVED;
	*fdflags(p, sv[1]) &= ~UF_RESERVED;
	error = copyout((caddr_t)sv, (caddr_t)uap->rsv,
	    2 * sizeof (int));
#if 0   /* old pipe(2) syscall compatability, unused these days */
	retval[0] = sv[0];		/* XXX ??? */
	retval[1] = sv[1];		/* XXX ??? */
#endif /* 0 */
	return (error);
free4:
	fdrelse(p, sv[1]);
	ffree(fp2);
free3:
	fdrelse(p, sv[0]);
	ffree(fp1);
free2:
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	(void)soclose(so2);
free1:
	(void)soclose(so1);
	return (error);
}

static int
sendit(p, s, mp, flags, retsize)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	int flags;
	register_t *retsize;
{
	struct file *fp;
	struct uio auio;
	register struct iovec *iov;
	register int i;
	struct mbuf *control;
	struct sockaddr *to;
	int len, error;
	struct socket *so;
#if KTRACE
	struct iovec *ktriov = NULL;
	struct uio ktruio;
#endif
	
	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_START, 0,0,0,0,0);

	if (error = getsock(p->p_fd, s, &fp))
	{
	    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
	    return (error);
	}

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_procp = p;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if (iov->iov_len < 0)
		{
		    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, EINVAL,0,0,0,0);
		    return (EINVAL);
		}

		if ((auio.uio_resid += iov->iov_len) < 0)
		{
		    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, EINVAL,0,0,0,0);
		    return (EINVAL);
		}
	}
	if (mp->msg_name) {
		error = getsockaddr(&to, mp->msg_name, mp->msg_namelen);
		if (error) {
		    KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
		    return (error);
		}
	} else
		to = 0;
	if (mp->msg_control) {
		if (mp->msg_controllen < sizeof(struct cmsghdr)
#ifdef COMPAT_OLDSOCK
		    && mp->msg_flags != MSG_COMPAT
#endif
		) {
			error = EINVAL;
			goto bad;
		}
		error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL);
		if (error)
			goto bad;
#ifdef COMPAT_OLDSOCK
		if (mp->msg_flags == MSG_COMPAT) {
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
	} else
		control = 0;

#if KTRACE    
    if (KTRPOINT(p, KTR_GENIO)) {
        int iovlen = auio.uio_iovcnt * sizeof (struct iovec);

        MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
        bcopy((caddr_t)auio.uio_iov, (caddr_t)ktriov, iovlen);
        ktruio = auio;
    }   
#endif
	len = auio.uio_resid;
	so = (struct socket *)fp->f_data;
	error = so->so_proto->pr_usrreqs->pru_sosend(so, to, &auio, 0, control,
						     flags);
	if (error) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
                /* Generation of SIGPIPE can be controlled per socket */
		if (error == EPIPE && !(so->so_flags & SOF_NOSIGPIPE))
			psignal(p, SIGPIPE);
	}
	if (error == 0)
		*retsize = len - auio.uio_resid;
#if KTRACE
	if (ktriov != NULL) {
		if (error == 0) {
			ktruio.uio_iov = ktriov;
			ktruio.uio_resid = retsize[0];
			ktrgenio(p->p_tracep, s, UIO_WRITE, &ktruio, error, -1);
		}
		FREE(ktriov, M_TEMP);
	}
#endif
bad:
	if (to)
		FREE(to, M_SONAME);
	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error,0,0,0,0);
	return (error);
}


struct sendto_args {
	int s;
	caddr_t buf;
	size_t len;
	int flags;
	caddr_t to;
	int tolen;
};

int
sendto(p, uap, retval)
	struct proc *p;
	register struct sendto_args /* {
		int	s;
		caddr_t	buf;
		size_t	len;
		int	flags;
		caddr_t	to;
		int	tolen;
	} */ *uap;
	register_t *retval;

{
	struct msghdr msg;
	struct iovec aiov;
	int stat;

	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_START, 0,0,0,0,0);

	msg.msg_name = uap->to;
	msg.msg_namelen = uap->tolen;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	stat = sendit(p, uap->s, &msg, uap->flags, retval);
	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_END, stat, *retval,0,0,0);
	return(stat);
}

#ifdef COMPAT_OLDSOCK
struct osend_args {
	int s;
	caddr_t buf;
	int len;
	int flags;
};

int
osend(p, uap, retval)
	struct proc *p;
	register struct osend_args /* {
		int	s;
		caddr_t	buf;
		int	len;
		int	flags;
	} */ *uap;
	register_t *retval;

{
	struct msghdr msg;
	struct iovec aiov;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = 0;
	return (sendit(p, uap->s, &msg, uap->flags, retval));
}
struct osendmsg_args {
	int s;
	caddr_t msg;
	int flags;
};

int
osendmsg(p, uap, retval)
	struct proc *p;
	register struct osendmsg_args /* {
		int	s;
		caddr_t	msg;
		int	flags;
	} */ *uap;
	register_t *retval;

{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	error = copyin(uap->msg, (caddr_t)&msg, sizeof (struct omsghdr));
	if (error)
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		      M_WAITOK);
	} else
		iov = aiov;
	error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	msg.msg_flags = MSG_COMPAT;
	msg.msg_iov = iov;
	error = sendit(p, uap->s, &msg, uap->flags, retval);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}
#endif

struct sendmsg_args {
	int s;
	caddr_t msg;
	int flags;
};

int
sendmsg(p, uap, retval)
	struct proc *p;
	register struct sendmsg_args *uap;
	register_t *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_START, 0,0,0,0,0);
	if (error = copyin(uap->msg, (caddr_t)&msg, sizeof (msg)))
	{
	    KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error,0,0,0,0);
	    return (error);
	}

	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
	  if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
	    KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, EMSGSIZE,0,0,0,0);
			return (EMSGSIZE);
	  }
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else
		iov = aiov;
	if (msg.msg_iovlen &&
	    (error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)))))
		goto done;
	msg.msg_iov = iov;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	error = sendit(p, uap->s, &msg, uap->flags, retval);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error,0,0,0,0);
	return (error);
}

static int
recvit(p, s, mp, namelenp, retval)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	caddr_t namelenp;
	register_t *retval;
{
	struct file *fp;
	struct uio auio;
	register struct iovec *iov;
	register int i;
	int len, error;
	struct mbuf *m, *control = 0;
	caddr_t ctlbuf;
	struct socket *so;
	struct sockaddr *fromsa = 0;
#if KTRACE
	struct iovec *ktriov = NULL;
	struct uio ktruio;
#endif

	KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_START, 0,0,0,0,0);
	if (error = getsock(p->p_fd, s, &fp))
	{
	    KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, error,0,0,0,0);
	    return (error);
	}

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = p;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
	  if ((auio.uio_resid += iov->iov_len) < 0) {
	    KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, EINVAL,0,0,0,0);
	    return (EINVAL);
	  }
	}
#if KTRACE
	if (KTRPOINT(p, KTR_GENIO)) {
		int iovlen = auio.uio_iovcnt * sizeof (struct iovec);

		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy((caddr_t)auio.uio_iov, (caddr_t)ktriov, iovlen);
		ktruio = auio;
	}
#endif
	len = auio.uio_resid;
	so = (struct socket *)fp->f_data;
	error = so->so_proto->pr_usrreqs->pru_soreceive(so, &fromsa, &auio,
	    (struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
	    &mp->msg_flags);
	if (error) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
#if KTRACE
	if (ktriov != NULL) {
		if (error == 0) {
			ktruio.uio_iov = ktriov;
			ktruio.uio_resid = len - auio.uio_resid;
			ktrgenio(p->p_tracep, s, UIO_WRITE, &ktruio, error, -1);
		}
		FREE(ktriov, M_TEMP);
	}
#endif
	if (error)
		goto out;
	*retval = len - auio.uio_resid;
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
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				((struct osockaddr *)fromsa)->sa_family =
				    fromsa->sa_family;
#endif
			error = copyout(fromsa,
			    (caddr_t)mp->msg_name, (unsigned)len);
			if (error)
				goto out;
		}
		mp->msg_namelen = len;
		if (namelenp &&
		    (error = copyout((caddr_t)&len, namelenp, sizeof (int)))) {
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				error = 0;	/* old recvfrom didn't check */
			else
#endif
			goto out;
		}
	}
	if (mp->msg_control) {
#ifdef COMPAT_OLDSOCK
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
		ctlbuf = (caddr_t) mp->msg_control;

		while (m && len > 0) {
			unsigned int tocopy;

			if (len >= m->m_len) 
				tocopy = m->m_len;
			else {
				mp->msg_flags |= MSG_CTRUNC;
				tocopy = len;
			}
		
			if (error = copyout((caddr_t)mtod(m, caddr_t),
					ctlbuf, tocopy))
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
	return (error);
}


struct recvfrom_args  {
    int	s;
    caddr_t	buf;
    size_t	len;
    int	flags;
    caddr_t	from;
    int	*fromlenaddr;
};

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
	struct msghdr msg;
	struct iovec aiov;
	int error;

	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_START, 0,0,0,0,0);

	if (uap->fromlenaddr) {
		error = copyin((caddr_t)uap->fromlenaddr,
		    (caddr_t)&msg.msg_namelen, sizeof (msg.msg_namelen));
		if (error)
			return (error);
	} else
		msg.msg_namelen = 0;
	msg.msg_name = uap->from;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_END, error,0,0,0,0);
	return (recvit(p, uap->s, &msg, (caddr_t)uap->fromlenaddr, retval));
}

#ifdef COMPAT_OLDSOCK
int
orecvfrom(p, uap, retval)
	struct proc *p;
	struct recvfrom_args *uap;
	register_t *retval;
{

	uap->flags |= MSG_COMPAT;
	return (recvfrom(p, uap));
}
#endif


#ifdef COMPAT_OLDSOCK
struct	orecv_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};

int
orecv(p, uap, retval)
	struct proc *p;
	struct	orecv_args	*uap;
	register_t *retval;
{
	struct msghdr msg;
	struct iovec aiov;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	return (recvit(p, uap->s, &msg, (caddr_t)0, retval));
}

/*
 * Old recvmsg.  This code takes advantage of the fact that the old msghdr
 * overlays the new one, missing only the flags, and with the (old) access
 * rights where the control fields are now.
 */
struct orecvmsg_args  {
	int	s;
	struct	omsghdr *msg;
	int	flags;
};

int
orecvmsg(p, uap, retval)
	struct proc *p;
	struct orecvmsg_args *uap;
	register_t *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	error = copyin((caddr_t)uap->msg, (caddr_t)&msg,
	    sizeof (struct omsghdr));
	if (error)
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		      M_WAITOK);
	} else
		iov = aiov;
	msg.msg_flags = uap->flags | MSG_COMPAT;
	error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	msg.msg_iov = iov;
	error = recvit(p, uap->s, &msg, (caddr_t)&uap->msg->msg_namelen, retval);

	if (msg.msg_controllen && error == 0)
		error = copyout((caddr_t)&msg.msg_controllen,
		    (caddr_t)&uap->msg->msg_accrightslen, sizeof (int));
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}
#endif

struct recvmsg_args  {
	int	s;
	struct	msghdr *msg;
	int	flags;
};

int
recvmsg(p, uap, retval)
	struct proc *p;
	struct recvmsg_args *uap;
	register_t *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *uiov, *iov;
	register int error;

	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_START, 0,0,0,0,0);
	if (error = copyin((caddr_t)uap->msg, (caddr_t)&msg,
	    sizeof (msg)))
	{
	    	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error,0,0,0,0);
		return (error);
	}

	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
	  if ((u_int)msg.msg_iovlen >= UIO_MAXIOV) {
		    KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, EMSGSIZE,0,0,0,0);
		    return (EMSGSIZE);
	  }
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else
		iov = aiov;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = uap->flags &~ MSG_COMPAT;
#else
	msg.msg_flags = uap->flags;
#endif
	uiov = msg.msg_iov;
	msg.msg_iov = iov;
	error = copyin((caddr_t)uiov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)));
	if (error)
		goto done;
	error = recvit(p, uap->s, &msg, (caddr_t)0, retval);
	if (!error) {
		msg.msg_iov = uiov;
		error = copyout((caddr_t)&msg, (caddr_t)uap->msg, sizeof(msg));
	}
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error,0,0,0,0);
	return (error);
}

/* ARGSUSED */
struct shutdown_args  {
	int	s;
	int	how;
};

int
shutdown(p, uap, retval)
	struct proc *p;
	struct shutdown_args *uap;
	register_t *retval;
{
	struct file *fp;
	int error;

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	return (soshutdown((struct socket *)fp->f_data, uap->how));
}





/* ARGSUSED */
struct setsockopt_args  {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	valsize;
};

int
setsockopt(p, uap, retval)
	struct proc *p;
	struct setsockopt_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct sockopt sopt;
	int error;

	if (uap->val == 0 && uap->valsize != 0)
		return (EFAULT);
	if (uap->valsize < 0)
		return (EINVAL);

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = uap->level;
	sopt.sopt_name = uap->name;
	sopt.sopt_val = uap->val;
	sopt.sopt_valsize = uap->valsize;
	sopt.sopt_p = p;

	return (sosetopt((struct socket *)fp->f_data, &sopt));
}



int
getsockopt(p, uap, retval)
	struct proc *p;
	struct getsockopt_args  *uap;
	register_t *retval;
{
	int	valsize, error;
	struct	file *fp;
	struct	sockopt sopt;

	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		return (error);
	if (uap->val) {
		error = copyin((caddr_t)uap->avalsize, (caddr_t)&valsize,
		    sizeof (valsize));
		if (error)
			return (error);
		if (valsize < 0)
			return (EINVAL);
	} else
		valsize = 0;

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = uap->level;
	sopt.sopt_name = uap->name;
	sopt.sopt_val = uap->val;
	sopt.sopt_valsize = (size_t)valsize; /* checked non-negative above */
	sopt.sopt_p = p;

	error = sogetopt((struct socket *)fp->f_data, &sopt);
	if (error == 0) {
		valsize = sopt.sopt_valsize;
		error = copyout((caddr_t)&valsize,
				(caddr_t)uap->avalsize, sizeof (valsize));
	}
	return (error);
}



struct pipe_args {
	int	dummy;
};
/* ARGSUSED */
int
pipe(p, uap, retval)
	struct proc *p;
	struct pipe_args *uap;
	register_t *retval;
{
	struct file *rf, *wf;
	struct socket *rso, *wso;
	int fd, error;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	if (error = socreate(AF_UNIX, &rso, SOCK_STREAM, 0)) {
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		return (error);
	}
	if (error = socreate(AF_UNIX, &wso, SOCK_STREAM, 0)) {
		goto free1;
	}
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	error = falloc(p, &rf, &fd);
	if (error)
		goto free2;
	retval[0] = fd;
	rf->f_flag = FREAD;
	rf->f_type = DTYPE_SOCKET;
	rf->f_ops = &socketops;
	rf->f_data = (caddr_t)rso;
	if (error = falloc(p, &wf, &fd))
		goto free3;
	wf->f_flag = FWRITE;
	wf->f_type = DTYPE_SOCKET;
	wf->f_ops = &socketops;
	wf->f_data = (caddr_t)wso;
	retval[1] = fd;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	error = unp_connect2(wso, rso);
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	if (error)
		goto free4;
	*fdflags(p, retval[0]) &= ~UF_RESERVED;
	*fdflags(p, retval[1]) &= ~UF_RESERVED;
	return (0);
free4:
	fdrelse(p, retval[1]);
	ffree(wf);
free3:
	fdrelse(p, retval[0]);
	ffree(rf);
free2:
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	(void)soclose(wso);
free1:
	(void)soclose(rso);
	
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	return (error);
}


/*
 * Get socket name.
 */
/* ARGSUSED */
static int
getsockname1(p, uap, retval, compat)
	struct proc *p;
	register struct getsockname_args *uap;
	register_t *retval;
	int compat;
{
	struct file *fp;
	register struct socket *so;
	struct sockaddr *sa;
	u_int len;
	int error;

	error = getsock(p->p_fd, uap->fdes, &fp);
	if (error)
		return (error);
	error = copyin((caddr_t)uap->alen, (caddr_t)&len, sizeof (len));
	if (error)
		return (error);
	so = (struct socket *)fp->f_data;
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}

	len = MIN(len, sa->sa_len);
#ifdef COMPAT_OLDSOCK
	if (compat)
		((struct osockaddr *)sa)->sa_family = sa->sa_family;
#endif
	error = copyout(sa, (caddr_t)uap->asa, (u_int)len);
	if (error == 0)
gotnothing:
		error = copyout((caddr_t)&len, (caddr_t)uap->alen,
		    sizeof (len));
bad:
	if (sa)
		FREE(sa, M_SONAME);
	return (error);
}

int
getsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	register_t *retval;
{

	return (getsockname1(p, uap, retval, 0));
}

#ifdef COMPAT_OLDSOCK
int
ogetsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	register_t *retval;
{

	return (getsockname1(p, uap, retval, 1));
}
#endif /* COMPAT_OLDSOCK */

/*
 * Get name of peer for connected socket.
 */
/* ARGSUSED */
int
getpeername1(p, uap, retval, compat)
	struct proc *p;
	register struct getpeername_args *uap;
	register_t *retval;
	int compat;
{
	struct file *fp;
	register struct socket *so;
	struct sockaddr *sa;
	u_int len;
	int error;

	error = getsock(p->p_fd, uap->fdes, &fp);
	if (error)
		return (error);
	so = (struct socket *)fp->f_data;
	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING)) == 0)
		return (ENOTCONN);
	error = copyin((caddr_t)uap->alen, (caddr_t)&len, sizeof (len));
	if (error)
		return (error);
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}
	len = MIN(len, sa->sa_len);
#ifdef COMPAT_OLDSOCK
	if (compat)
		((struct osockaddr *)sa)->sa_family =
		    sa->sa_family;
#endif
	error = copyout(sa, (caddr_t)uap->asa, (u_int)len);
	if (error)
		goto bad;
gotnothing:
	error = copyout((caddr_t)&len, (caddr_t)uap->alen, sizeof (len));
bad:
	if (sa) FREE(sa, M_SONAME);
	return (error);
}

int
getpeername(p, uap, retval)
	struct proc *p;
	struct getpeername_args *uap;
	register_t *retval;
{

	return (getpeername1(p, uap, retval, 0));
}

#ifdef COMPAT_OLDSOCK
int
ogetpeername(p, uap, retval)
	struct proc *p;
	struct ogetpeername_args *uap;
	register_t *retval;
{

	/* XXX uap should have type `getpeername_args *' to begin with. */
	return (getpeername1(p, (struct getpeername_args *)uap, retval, 1));
}
#endif /* COMPAT_OLDSOCK */

int
sockargs(mp, buf, buflen, type)
	struct mbuf **mp;
	caddr_t buf;
	int buflen, type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
#ifdef COMPAT_OLDSOCK
		if (type == MT_SONAME && (u_int)buflen <= 112)
			buflen = MLEN;		/* unix domain compat. hack */
		else
#endif
		return (EINVAL);
	}
	m = m_get(M_WAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	m->m_len = buflen;
	error = copyin(buf, mtod(m, caddr_t), (u_int)buflen);
	if (error)
		(void) m_free(m);
	else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);

#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
			if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
				sa->sa_family = sa->sa_len;
#endif
			sa->sa_len = buflen;
		}
	}
	return (error);
}

int
getsockaddr(namp, uaddr, len)
	struct sockaddr **namp;
	caddr_t uaddr;
	size_t  len;
{
	struct sockaddr *sa;
	int error;

	if (len > SOCK_MAXADDRLEN)
		return ENAMETOOLONG;

	if (len == 0)
	     return EINVAL;

	MALLOC(sa, struct sockaddr *, len, M_SONAME, M_WAITOK);
	error = copyin(uaddr, sa, len);
	if (error) {
		FREE(sa, M_SONAME);
	} else {
#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = len;
		*namp = sa;
	}
	return error;
}

int
getsock(fdp, fdes, fpp)
	struct filedesc *fdp;
	int fdes;
	struct file **fpp;
{
	register struct file *fp;

	if ((unsigned)fdes >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[fdes]) == NULL ||
	    (fdp->fd_ofileflags[fdes] & UF_RESERVED))
		return (EBADF);
	if (fp->f_type != DTYPE_SOCKET)
		return (ENOTSOCK);
	*fpp = fp;
	return (0);
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
	sf_base = kmem_alloc_pageable(kernel_map, nsfbufs * PAGE_SIZE);
	sf_bufs = _MALLOC(nsfbufs * sizeof(struct sf_buf), M_TEMP, M_NOWAIT);
	bzero(sf_bufs, nsfbufs * sizeof(struct sf_buf));
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
	int s;

	s = splimp();
	while ((sf = SLIST_FIRST(&sf_freelist)) == NULL) {
		sf_buf_alloc_want = 1;
		tsleep(&sf_freelist, PVM, "sfbufa", 0);
	}
	SLIST_REMOVE_HEAD(&sf_freelist, free_list);
	splx(s);
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
	int s;

	sf = dtosf(addr);
	if (sf->refcnt == 0)
		panic("sf_buf_free: freeing free sf_buf");
	sf->refcnt--;
	if (sf->refcnt == 0) {
		pmap_qremove((vm_offset_t)addr, 1);
		m = sf->m;
		s = splvm();
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
		splx(s);
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
	struct file *fp;
	struct filedesc *fdp = p->p_fd;
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

	/*
	 * Do argument checking. Must be a regular file in, stream
	 * type and connected socket out, positive offset.
	 */
	if (((u_int)uap->fd) >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[uap->fd]) == NULL ||
	    (fp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto done;
	}
	if (fp->f_type != DTYPE_VNODE) {
		error = EINVAL;
		goto done;
	}
	vp = (struct vnode *)fp->f_data;
	obj = vp->v_object;
	if (vp->v_type != VREG || obj == NULL) {
		error = EINVAL;
		goto done;
	}
	error = getsock(p->p_fd, uap->s, &fp);
	if (error)
		goto done;
	so = (struct socket *)fp->f_data;
	if (so->so_type != SOCK_STREAM) {
		error = EINVAL;
		goto done;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto done;
	}
	if (uap->offset < 0) {
		error = EINVAL;
		goto done;
	}

	/*
	 * If specified, get the pointer to the sf_hdtr struct for
	 * any headers/trailers.
	 */
	if (uap->hdtr != NULL) {
		error = copyin(uap->hdtr, &hdtr, sizeof(hdtr));
		if (error)
			goto done;
		/*
		 * Send any headers. Wimp out and use writev(2).
		 */
		if (hdtr.headers != NULL) {
			nuap.fd = uap->s;
			nuap.iovp = hdtr.headers;
			nuap.iovcnt = hdtr.hdr_cnt;
			error = writev(p, &nuap);
			if (error)
				goto done;
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
			sbunlock(&so->so_snd);
			goto done;
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
			bsize = vp->v_mount->mnt_stat.f_iosize;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			aiov.iov_base = 0;
			aiov.iov_len = MAXBSIZE;
			auio.uio_resid = MAXBSIZE;
			auio.uio_offset = trunc_page(off);
			auio.uio_segflg = UIO_NOCOPY;
			auio.uio_rw = UIO_READ;
			auio.uio_procp = p;
			vn_lock(vp, LK_SHARED | LK_NOPAUSE | LK_RETRY, p);
			error = VOP_READ(vp, &auio, IO_VMIO | ((MAXBSIZE / bsize) << 16),
			        p->p_ucred);
			VOP_UNLOCK(vp, 0, p);
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
				sbunlock(&so->so_snd);
				goto done;
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
					splx(s);
					goto retry_lookup;
				}
				splx(s);
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
		s = splnet();
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
			sbunlock(&so->so_snd);
			splx(s);
			goto done;
		}
		/*
		 * Wait for socket space to become available. We do this just
		 * after checking the connection state above in order to avoid
		 * a race condition with sbwait().
		 */
		if (sbspace(&so->so_snd) < so->so_snd.sb_lowat) {
			if (so->so_state & SS_NBIO) {
				m_freem(m);
				sbunlock(&so->so_snd);
				splx(s);
				error = EAGAIN;
				goto done;
			}
			error = sbwait(&so->so_snd);
			/*
			 * An error from sbwait usually indicates that we've
			 * been interrupted by a signal. If we've sent anything
			 * then return bytes sent, otherwise return the error.
			 */
			if (error) {
				m_freem(m);
				sbunlock(&so->so_snd);
				splx(s);
				goto done;
			}
			goto retry_space;
		}
		error = (*so->so_proto->pr_usrreqs->pru_send)(so, 0, m, 0, 0, p);
		splx(s);
		if (error) {
			sbunlock(&so->so_snd);
			goto done;
		}
	}
	sbunlock(&so->so_snd);

	/*
	 * Send trailers. Wimp out and use writev(2).
	 */
	if (uap->hdtr != NULL && hdtr.trailers != NULL) {
			nuap.fd = uap->s;
			nuap.iovp = hdtr.trailers;
			nuap.iovcnt = hdtr.trl_cnt;
			error = writev(p, &nuap);
			if (error)
				goto done;
			sbytes += p->p_retval[0];
	}

done:
	if (uap->sbytes != NULL) {
		copyout(&sbytes, uap->sbytes, sizeof(off_t));
	}
	return (error);
}

#endif
