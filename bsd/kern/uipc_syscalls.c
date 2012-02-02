/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <kern/lock.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/uio_internal.h>
#include <sys/kauth.h>
#include <kern/task.h>

#include <security/audit/audit.h>

#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <netinet/in.h>
#include <net/route.h>
#include <netinet/in_pcb.h>

#if CONFIG_MACF_SOCKET_SUBSET
#include <security/mac_framework.h>
#endif /* MAC_SOCKET_SUBSET */

#define	f_flag f_fglob->fg_flag
#define	f_type f_fglob->fg_type
#define	f_msgcount f_fglob->fg_msgcount
#define	f_cred f_fglob->fg_cred
#define	f_ops f_fglob->fg_ops
#define	f_offset f_fglob->fg_offset
#define	f_data f_fglob->fg_data


#define	DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETSOCK, 0)
#define	DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETSOCK, 2)
#define	DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETSOCK, 1)
#define	DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETSOCK, 3)
#define	DBG_FNC_SENDMSG		NETDBG_CODE(DBG_NETSOCK, (1 << 8) | 1)
#define	DBG_FNC_SENDTO		NETDBG_CODE(DBG_NETSOCK, (2 << 8) | 1)
#define	DBG_FNC_SENDIT		NETDBG_CODE(DBG_NETSOCK, (3 << 8) | 1)
#define	DBG_FNC_RECVFROM	NETDBG_CODE(DBG_NETSOCK, (5 << 8))
#define	DBG_FNC_RECVMSG		NETDBG_CODE(DBG_NETSOCK, (6 << 8))
#define	DBG_FNC_RECVIT		NETDBG_CODE(DBG_NETSOCK, (7 << 8))
#define	DBG_FNC_SENDFILE	NETDBG_CODE(DBG_NETSOCK, (10 << 8))
#define	DBG_FNC_SENDFILE_WAIT	NETDBG_CODE(DBG_NETSOCK, ((10 << 8) | 1))
#define	DBG_FNC_SENDFILE_READ	NETDBG_CODE(DBG_NETSOCK, ((10 << 8) | 2))
#define	DBG_FNC_SENDFILE_SEND	NETDBG_CODE(DBG_NETSOCK, ((10 << 8) | 3))


#define	HACK_FOR_4056224 1
#if HACK_FOR_4056224
static pid_t last_pid_4056224 = 0;
#endif /* HACK_FOR_4056224 */

/* TODO: should be in header file */
int falloc_locked(proc_t, struct fileproc **, int *, vfs_context_t, int);

static int sendit(struct proc *, int, struct user_msghdr *, uio_t, int,
    int32_t *);
static int recvit(struct proc *, int, struct user_msghdr *, uio_t, user_addr_t,
    int32_t *);
static int getsockaddr(struct socket *, struct sockaddr **, user_addr_t,
    size_t, boolean_t);
static int getsockaddr_s(struct socket *, struct sockaddr_storage *,
    user_addr_t, size_t, boolean_t);
#if SENDFILE
static void alloc_sendpkt(int, size_t, unsigned int *, struct mbuf **,
    boolean_t);
#endif /* SENDFILE */

/*
 * System call interface to the socket abstraction.
 */

extern	struct fileops socketops;

/*
 * Returns:	0			Success
 *		EACCES			Mandatory Access Control failure
 *	falloc:ENFILE
 *	falloc:EMFILE
 *	falloc:ENOMEM
 *	socreate:EAFNOSUPPORT
 *	socreate:EPROTOTYPE
 *	socreate:EPROTONOSUPPORT
 *	socreate:ENOBUFS
 *	socreate:ENOMEM
 *	socreate:EISCONN
 *	socreate:???			[other protocol families, IPSEC]
 */
int
socket(struct proc *p, struct socket_args *uap, int32_t *retval)
{
	struct socket *so;
	struct fileproc *fp;
	int fd, error;

	AUDIT_ARG(socket, uap->domain, uap->type, uap->protocol);
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_create(kauth_cred_get(), uap->domain,
	    uap->type, uap->protocol)) != 0)
		return (error);
#endif /* MAC_SOCKET_SUBSET */

	error = falloc(p, &fp, &fd, vfs_context_current());
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
		thread_t			thread;
		struct uthread		*ut;
		
		thread = current_thread();
		ut = get_bsdthread_info(thread);
			
		/* if this is a backgrounded thread then throttle all new sockets */
#if !CONFIG_EMBEDDED
		if (proc_get_selfthread_isbackground() != 0)
#else /* !CONFIG_EMBEDDED */
		if ( (ut->uu_flag & UT_BACKGROUND) != 0 ) 
#endif /* !CONFIG_EMBEDDED */
		{
			so->so_traffic_mgt_flags |= TRAFFIC_MGT_SO_BACKGROUND;
			so->so_background_thread = thread;
		}
		fp->f_data = (caddr_t)so;

		proc_fdlock(p);
		procfdtbl_releasefd(p, fd, NULL);

		fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);

		*retval = fd;
	}
	return (error);
}

/*
 * Returns:	0			Success
 *		EDESTADDRREQ		Destination address required
 *		EBADF			Bad file descriptor
 *		EACCES			Mandatory Access Control failure
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	getsockaddr:ENAMETOOLONG	Filename too long
 *	getsockaddr:EINVAL		Invalid argument
 *	getsockaddr:ENOMEM		Not enough space
 *	getsockaddr:EFAULT		Bad address
 *	sobind:???
 */
/* ARGSUSED */
int
bind(__unused proc_t p, struct bind_args *uap, __unused int32_t *retval)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = NULL;
	struct socket *so;
	boolean_t want_free = TRUE;
	int error;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(uap->s, &so);
	if (error != 0)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	if (uap->name == USER_ADDR_NULL) {
		error = EDESTADDRREQ;
		goto out;
	}
	if (uap->namelen > sizeof (ss)) {
		error = getsockaddr(so, &sa, uap->name, uap->namelen, TRUE);
	} else {
		error = getsockaddr_s(so, &ss, uap->name, uap->namelen, TRUE);
		if (error == 0) {
			sa = (struct sockaddr *)&ss;
			want_free = FALSE;
		}
	}
	if (error != 0)
		goto out;
	AUDIT_ARG(sockaddr, vfs_context_cwd(vfs_context_current()), sa);
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_bind(kauth_cred_get(), so, sa)) == 0)
		error = sobind(so, sa);
#else
		error = sobind(so, sa);
#endif /* MAC_SOCKET_SUBSET */
	if (want_free)
		FREE(sa, M_SONAME);
out:
	file_drop(uap->s);
	return (error);
}

/*
 * Returns:	0			Success
 *		EBADF
 *		EACCES			Mandatory Access Control failure
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	solisten:EINVAL
 *	solisten:EOPNOTSUPP
 *	solisten:???
 */
int
listen(__unused struct proc *p, struct listen_args *uap,
    __unused int32_t *retval)
{
	int error;
	struct socket *so;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	if (so != NULL)
#if CONFIG_MACF_SOCKET_SUBSET
	{
		error = mac_socket_check_listen(kauth_cred_get(), so);
		if (error == 0)
			error = solisten(so, uap->backlog);
	}
#else
		error =  solisten(so, uap->backlog);
#endif /* MAC_SOCKET_SUBSET */
	else
		error = EBADF;

	file_drop(uap->s);
	return (error);
}

/*
 * Returns:	fp_getfsock:EBADF	Bad file descriptor
 *		fp_getfsock:EOPNOTSUPP	...
 *		xlate => :ENOTSOCK	Socket operation on non-socket
 *		:EFAULT			Bad address on copyin/copyout
 *		:EBADF			Bad file descriptor
 *		:EOPNOTSUPP		Operation not supported on socket
 *		:EINVAL			Invalid argument
 *		:EWOULDBLOCK		Operation would block
 *		:ECONNABORTED		Connection aborted
 *		:EINTR			Interrupted function
 *		:EACCES			Mandatory Access Control failure
 *		falloc_locked:ENFILE	Too many files open in system
 *		falloc_locked::EMFILE	Too many open files
 *		falloc_locked::ENOMEM	Not enough space
 *		0			Success
 */
int
accept_nocancel(struct proc *p, struct accept_nocancel_args *uap,
    int32_t *retval)
{
	struct fileproc *fp;
	struct sockaddr *sa = NULL;
	socklen_t namelen;
	int error;
	struct socket *head, *so = NULL;
	lck_mtx_t *mutex_held;
	int fd = uap->s;
	int newfd;
	short fflag;		/* type must match fp->f_flag */
	int dosocklock = 0;

	*retval = -1;

	AUDIT_ARG(fd, uap->s);

	if (uap->name) {
		error = copyin(uap->anamelen, (caddr_t)&namelen,
		    sizeof (socklen_t));
		if (error)
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
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_accept(kauth_cred_get(), head)) != 0)
		goto out;
#endif /* MAC_SOCKET_SUBSET */

	socket_lock(head, 1);

	if (head->so_proto->pr_getlock != NULL)  {
		mutex_held = (*head->so_proto->pr_getlock)(head, 0);
		dosocklock = 1;
	} else {
		mutex_held = head->so_proto->pr_domain->dom_mtx;
		dosocklock = 0;
	}

	if ((head->so_options & SO_ACCEPTCONN) == 0) {
		if ((head->so_proto->pr_flags & PR_CONNREQUIRED) == 0) {
			error = EOPNOTSUPP;
		} else {
			/* POSIX: The socket is not accepting connections */
			error = EINVAL;
		}
		socket_unlock(head, 1);
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
			panic("accept: head=%p refcount=%d\n", head,
			    head->so_usecount);
		error = msleep((caddr_t)&head->so_timeo, mutex_held,
		    PSOCK | PCATCH, "accept", 0);
		if (head->so_usecount < 1)
			panic("accept: 2 head=%p refcount=%d\n", head,
			    head->so_usecount);
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
	/* unlock head to avoid deadlock with select, keep a ref on head */
	socket_unlock(head, 0);

#if CONFIG_MACF_SOCKET_SUBSET
	/*
	 * Pass the pre-accepted socket to the MAC framework. This is
	 * cheaper than allocating a file descriptor for the socket,
	 * calling the protocol accept callback, and possibly freeing
	 * the file descriptor should the MAC check fails.
	 */
	if ((error = mac_socket_check_accepted(kauth_cred_get(), so)) != 0) {
		so->so_state &= ~(SS_NOFDREF | SS_COMP);
		so->so_head = NULL;
		soclose(so);
		/* Drop reference on listening socket */
		sodereference(head);
		goto out;
	}
#endif /* MAC_SOCKET_SUBSET */

	/*
	 * Pass the pre-accepted socket to any interested socket filter(s).
	 * Upon failure, the socket would have been closed by the callee.
	 */
	if (so->so_filt != NULL && (error = soacceptfilter(so)) != 0) {
		/* Drop reference on listening socket */
		sodereference(head);
		/* Propagate socket filter's error code to the caller */
		goto out;
	}

	fflag = fp->f_flag;
	error = falloc(p, &fp, &newfd, vfs_context_current());
	if (error) {
		/*
		 * Probably ran out of file descriptors. Put the
		 * unaccepted connection back onto the queue and
		 * do another wakeup so some other process might
		 * have a chance at it.
		 */
		socket_lock(head, 0);
		TAILQ_INSERT_HEAD(&head->so_comp, so, so_list);
		head->so_qlen++;
		wakeup_one((caddr_t)&head->so_timeo);
		socket_unlock(head, 1);
		goto out;
	}
	*retval = newfd;
	fp->f_type = DTYPE_SOCKET;
	fp->f_flag = fflag;
	fp->f_ops = &socketops;
	fp->f_data = (caddr_t)so;
	socket_lock(head, 0);
	if (dosocklock)
		socket_lock(so, 1);
	so->so_state &= ~SS_COMP;
	so->so_head = NULL;
	(void) soacceptlock(so, &sa, 0);
	socket_unlock(head, 1);
	if (sa == NULL) {
		namelen = 0;
		if (uap->name)
			goto gotnoname;
		error = 0;
		goto releasefd;
	}
	AUDIT_ARG(sockaddr, vfs_context_cwd(vfs_context_current()), sa);

	if (uap->name) {
		socklen_t	sa_len;

		/* save sa_len before it is destroyed */
		sa_len = sa->sa_len;
		namelen = MIN(namelen, sa_len);
		error = copyout(sa, uap->name, namelen);
		if (!error)
			/* return the actual, untruncated address length */
			namelen = sa_len;
gotnoname:
		error = copyout((caddr_t)&namelen, uap->anamelen,
		    sizeof (socklen_t));
	}
	FREE(sa, M_SONAME);

releasefd:
	/*
	 * If the socket has been marked as inactive by sosetdefunct(),
	 * disallow further operations on it.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		sodefunct(current_proc(), so,
		    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL);
	}

	if (dosocklock)
		socket_unlock(so, 1);

	proc_fdlock(p);
	procfdtbl_releasefd(p, newfd, NULL);
	fp_drop(p, newfd, fp, 1);
	proc_fdunlock(p);

out:
	file_drop(fd);
	return (error);
}

int
accept(struct proc *p, struct accept_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(accept_nocancel(p, (struct accept_nocancel_args *)uap, retval));
}

/*
 * Returns:	0			Success
 *		EBADF			Bad file descriptor
 *		EALREADY		Connection already in progress
 *		EINPROGRESS		Operation in progress
 *		ECONNABORTED		Connection aborted
 *		EINTR			Interrupted function
 *		EACCES			Mandatory Access Control failure
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	getsockaddr:ENAMETOOLONG	Filename too long
 *	getsockaddr:EINVAL		Invalid argument
 *	getsockaddr:ENOMEM		Not enough space
 *	getsockaddr:EFAULT		Bad address
 *	soconnectlock:EOPNOTSUPP
 *	soconnectlock:EISCONN
 *	soconnectlock:???		[depends on protocol, filters]
 *	msleep:EINTR
 *
 * Imputed:	so_error		error may be set from so_error, which
 *					may have been set by soconnectlock.
 */
/* ARGSUSED */
int
connect(struct proc *p, struct connect_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(connect_nocancel(p, (struct connect_nocancel_args *)uap, retval));
}

int
connect_nocancel(__unused proc_t p, struct connect_nocancel_args *uap, __unused int32_t *retval)
{
	struct socket *so;
	struct sockaddr_storage ss;
	struct sockaddr *sa = NULL;
	lck_mtx_t *mutex_held;
	boolean_t want_free = TRUE;
	int error;
	int fd = uap->s;
	boolean_t dgram;

	AUDIT_ARG(fd, uap->s);
	error = file_socket(fd, &so);
	if (error != 0)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}

	/*
	 * Ask getsockaddr{_s} to not translate AF_UNSPEC to AF_INET
	 * if this is a datagram socket; translate for other types.
	 */
	dgram = (so->so_type == SOCK_DGRAM);

	/* Get socket address now before we obtain socket lock */
	if (uap->namelen > sizeof (ss)) {
		error = getsockaddr(so, &sa, uap->name, uap->namelen, !dgram);
	} else {
		error = getsockaddr_s(so, &ss, uap->name, uap->namelen, !dgram);
		if (error == 0) {
			sa = (struct sockaddr *)&ss;
			want_free = FALSE;
		}
	}
	if (error != 0)
		goto out;

	AUDIT_ARG(sockaddr, vfs_context_cwd(vfs_context_current()), sa);
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_connect(kauth_cred_get(), so, sa)) != 0) {
		if (want_free)
			FREE(sa, M_SONAME);
		goto out;
	}
#endif /* MAC_SOCKET_SUBSET */
	socket_lock(so, 1);

	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		if (want_free)
			FREE(sa, M_SONAME);
		socket_unlock(so, 1);
		error = EALREADY;
		goto out;
	}
	error = soconnectlock(so, sa, 0);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		if (want_free)
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
		error = msleep((caddr_t)&so->so_timeo, mutex_held,
		    PSOCK | PCATCH, "connect", 0);
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
	if (want_free)
		FREE(sa, M_SONAME);
	if (error == ERESTART)
		error = EINTR;
out:
	file_drop(fd);
	return (error);
}

/*
 * Returns:	0			Success
 *	socreate:EAFNOSUPPORT
 *	socreate:EPROTOTYPE
 *	socreate:EPROTONOSUPPORT
 *	socreate:ENOBUFS
 *	socreate:ENOMEM
 *	socreate:EISCONN
 *	socreate:???			[other protocol families, IPSEC]
 *	falloc:ENFILE
 *	falloc:EMFILE
 *	falloc:ENOMEM
 *	copyout:EFAULT
 *	soconnect2:EINVAL
 *	soconnect2:EPROTOTYPE
 *	soconnect2:???			[other protocol families[
 */
int
socketpair(struct proc *p, struct socketpair_args *uap,
    __unused int32_t *retval)
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

	error = falloc(p, &fp1, &fd, vfs_context_current());
	if (error) {
		goto free2;
	}
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_type = DTYPE_SOCKET;
	fp1->f_ops = &socketops;
	fp1->f_data = (caddr_t)so1;
	sv[0] = fd;

	error = falloc(p, &fp2, &fd, vfs_context_current());
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

	if ((error = copyout(sv, uap->rsv, 2 * sizeof (int))) != 0)
		goto free4;

	proc_fdlock(p);
	procfdtbl_releasefd(p, sv[0], NULL);
	procfdtbl_releasefd(p, sv[1], NULL);
	fp_drop(p, sv[0], fp1, 1);
	fp_drop(p, sv[1], fp2, 1);
	proc_fdunlock(p);

	return (0);
free4:
	fp_free(p, sv[1], fp2);
free3:
	fp_free(p, sv[0], fp1);
free2:
	(void) soclose(so2);
free1:
	(void) soclose(so1);
	return (error);
}

/*
 * Returns:	0			Success
 *		EINVAL
 *		ENOBUFS
 *		EBADF
 *		EPIPE
 *		EACCES			Mandatory Access Control failure
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	getsockaddr:ENAMETOOLONG	Filename too long
 *	getsockaddr:EINVAL		Invalid argument
 *	getsockaddr:ENOMEM		Not enough space
 *	getsockaddr:EFAULT		Bad address
 *	<pru_sosend>:EACCES[TCP]
 *	<pru_sosend>:EADDRINUSE[TCP]
 *	<pru_sosend>:EADDRNOTAVAIL[TCP]
 *	<pru_sosend>:EAFNOSUPPORT[TCP]
 *	<pru_sosend>:EAGAIN[TCP]
 *	<pru_sosend>:EBADF
 *	<pru_sosend>:ECONNRESET[TCP]
 *	<pru_sosend>:EFAULT
 *	<pru_sosend>:EHOSTUNREACH[TCP]
 *	<pru_sosend>:EINTR
 *	<pru_sosend>:EINVAL
 *	<pru_sosend>:EISCONN[AF_INET]
 *	<pru_sosend>:EMSGSIZE[TCP]
 *	<pru_sosend>:ENETDOWN[TCP]
 *	<pru_sosend>:ENETUNREACH[TCP]
 *	<pru_sosend>:ENOBUFS
 *	<pru_sosend>:ENOMEM[TCP]
 *	<pru_sosend>:ENOTCONN[AF_INET]
 *	<pru_sosend>:EOPNOTSUPP
 *	<pru_sosend>:EPERM[TCP]
 *	<pru_sosend>:EPIPE
 *	<pru_sosend>:EWOULDBLOCK
 *	<pru_sosend>:???[TCP]		[ignorable: mostly IPSEC/firewall/DLIL]
 *	<pru_sosend>:???[AF_INET]	[whatever a filter author chooses]
 *	<pru_sosend>:???		[value from so_error]
 *	sockargs:???
 */
static int
sendit(struct proc *p, int s, struct user_msghdr *mp, uio_t uiop,
    int flags, int32_t *retval)
{
	struct mbuf *control = NULL;
	struct sockaddr_storage ss;
	struct sockaddr *to = NULL;
	boolean_t want_free = TRUE;
	int error;
	struct socket *so;
	user_ssize_t len;

	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	error = file_socket(s, &so);
	if (error) {
		KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error, 0, 0, 0, 0);
		return (error);
	}
	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	if (mp->msg_name != USER_ADDR_NULL) {
		if (mp->msg_namelen > sizeof (ss)) {
			error = getsockaddr(so, &to, mp->msg_name,
			    mp->msg_namelen, TRUE);
		} else {
			error = getsockaddr_s(so, &ss, mp->msg_name,
			    mp->msg_namelen, TRUE);
			if (error == 0) {
				to = (struct sockaddr *)&ss;
				want_free = FALSE;
			}
		}
		if (error != 0)
			goto out;
		AUDIT_ARG(sockaddr, vfs_context_cwd(vfs_context_current()), to);
	}
	if (mp->msg_control != USER_ADDR_NULL) {
		if (mp->msg_controllen < sizeof (struct cmsghdr)) {
			error = EINVAL;
			goto bad;
		}
		error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL);
		if (error != 0)
			goto bad;
	}

#if CONFIG_MACF_SOCKET_SUBSET
	/*
	 * We check the state without holding the socket lock;
	 * if a race condition occurs, it would simply result
	 * in an extra call to the MAC check function.
	 */
	if (!(so->so_state & SS_ISCONNECTED) &&
	    (error = mac_socket_check_send(kauth_cred_get(), so, to)) != 0)
		goto bad;
#endif /* MAC_SOCKET_SUBSET */

	len = uio_resid(uiop);
	error = so->so_proto->pr_usrreqs->pru_sosend(so, to, uiop, 0, control,
	    flags);
	if (error != 0) {
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
	if (to != NULL && want_free)
		FREE(to, M_SONAME);
out:
	KERNEL_DEBUG(DBG_FNC_SENDIT | DBG_FUNC_END, error, 0, 0, 0, 0);
	file_drop(s);
	return (error);
}

/*
 * Returns:	0			Success
 *		ENOMEM
 *	sendit:???			[see sendit definition in this file]
 *	write:???			[4056224: applicable for pipes]
 */
int
sendto(struct proc *p, struct sendto_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(sendto_nocancel(p, (struct sendto_nocancel_args *)uap, retval));
}

int
sendto_nocancel(struct proc *p, struct sendto_nocancel_args *uap, int32_t *retval)
{
	struct user_msghdr msg;
	int error;
	uio_t auio = NULL;

	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_START, 0, 0, 0, 0, 0);
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
	 * Temporary workaround to let send() and recv() work over
	 * a pipe for binary compatibility
	 * This will be removed in the release following Tiger
	 */
	if (error == ENOTSOCK) {
		struct fileproc *fp;

		if (fp_lookup(p, uap->s, &fp, 0) == 0) {
			(void) fp_drop(p, uap->s, fp, 0);

			if (fp->f_type == DTYPE_PIPE) {
				struct write_args write_uap;
				user_ssize_t write_retval;

				if (p->p_pid > last_pid_4056224) {
					last_pid_4056224 = p->p_pid;

					printf("%s[%d] uses send/recv "
					    "on a pipe\n", p->p_comm, p->p_pid);
				}

				bzero(&write_uap, sizeof (struct write_args));
				write_uap.fd = uap->s;
				write_uap.cbuf = uap->buf;
				write_uap.nbyte = uap->len;

				error = write(p, &write_uap, &write_retval);
				*retval = (int)write_retval;
			}
		}
	}
#endif /* HACK_FOR_4056224 */

	KERNEL_DEBUG(DBG_FNC_SENDTO | DBG_FUNC_END, error, *retval, 0, 0, 0);

	return (error);
}

/*
 * Returns:	0			Success
 *		ENOBUFS
 *	copyin:EFAULT
 *	sendit:???			[see sendit definition in this file]
 */
int
sendmsg(struct proc *p, struct sendmsg_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(sendmsg_nocancel(p, (struct sendmsg_nocancel_args *)uap, retval));
}

int
sendmsg_nocancel(struct proc *p, struct sendmsg_nocancel_args *uap, int32_t *retval)
{
	struct user32_msghdr msg32;
	struct user64_msghdr msg64;
	struct user_msghdr user_msg;
	caddr_t msghdrp;
	int	size_of_msghdr;
	int error;
	uio_t auio = NULL;
	struct user_iovec *iovp;

	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_START, 0, 0, 0, 0, 0);
	AUDIT_ARG(fd, uap->s);
	if (IS_64BIT_PROCESS(p)) {
		msghdrp = (caddr_t)&msg64;
		size_of_msghdr = sizeof (msg64);
	} else {
		msghdrp = (caddr_t)&msg32;
		size_of_msghdr = sizeof (msg32);
	}
	error = copyin(uap->msg, msghdrp, size_of_msghdr);
	if (error) {
		KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error, 0, 0, 0, 0);
		return (error);
	}

	if (IS_64BIT_PROCESS(p)) {
		user_msg.msg_flags = msg64.msg_flags;
		user_msg.msg_controllen = msg64.msg_controllen;
		user_msg.msg_control = msg64.msg_control;
		user_msg.msg_iovlen = msg64.msg_iovlen;
		user_msg.msg_iov = msg64.msg_iov;
		user_msg.msg_namelen = msg64.msg_namelen;
		user_msg.msg_name = msg64.msg_name;
	} else {
		user_msg.msg_flags = msg32.msg_flags;
		user_msg.msg_controllen = msg32.msg_controllen;
		user_msg.msg_control = msg32.msg_control;
		user_msg.msg_iovlen = msg32.msg_iovlen;
		user_msg.msg_iov = msg32.msg_iov;
		user_msg.msg_namelen = msg32.msg_namelen;
		user_msg.msg_name = msg32.msg_name;
	}

	if (user_msg.msg_iovlen <= 0 || user_msg.msg_iovlen > UIO_MAXIOV) {
		KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, EMSGSIZE,
		    0, 0, 0, 0);
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
		/*
		 * get location of iovecs within the uio.
		 * then copyin the iovecs from user space.
		 */
		iovp = uio_iovsaddr(auio);
		if (iovp == NULL) {
			error = ENOBUFS;
			goto done;
		}
		error = copyin_user_iovec_array(user_msg.msg_iov,
			IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
			user_msg.msg_iovlen, iovp);
		if (error)
			goto done;
		user_msg.msg_iov = CAST_USER_ADDR_T(iovp);

		/* finish setup of uio_t */
		uio_calculateresid(auio);
	} else {
		user_msg.msg_iov = 0;
	}

	/* msg_flags is ignored for send */
	user_msg.msg_flags = 0;

	error = sendit(p, uap->s, &user_msg, auio, uap->flags, retval);
done:
	if (auio != NULL) {
		uio_free(auio);
	}
	KERNEL_DEBUG(DBG_FNC_SENDMSG | DBG_FUNC_END, error, 0, 0, 0, 0);

	return (error);
}

/*
 * Returns:	0			Success
 *		ENOTSOCK
 *		EINVAL
 *		EBADF
 *		EACCES			Mandatory Access Control failure
 *	copyout:EFAULT
 *	fp_lookup:EBADF
 *	<pru_soreceive>:ENOBUFS
 *	<pru_soreceive>:ENOTCONN
 *	<pru_soreceive>:EWOULDBLOCK
 *	<pru_soreceive>:EFAULT
 *	<pru_soreceive>:EINTR
 *	<pru_soreceive>:EBADF
 *	<pru_soreceive>:EINVAL
 *	<pru_soreceive>:EMSGSIZE
 *	<pru_soreceive>:???
 *
 * Notes:	Additional return values from calls through <pru_soreceive>
 *		depend on protocols other than TCP or AF_UNIX, which are
 *		documented above.
 */
static int
recvit(struct proc *p, int s, struct user_msghdr *mp, uio_t uiop,
    user_addr_t namelenp, int32_t *retval)
{
	int len, error;
	struct mbuf *m, *control = 0;
	user_addr_t ctlbuf;
	struct socket *so;
	struct sockaddr *fromsa = 0;
	struct fileproc *fp;

	KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_START, 0, 0, 0, 0, 0);
	proc_fdlock(p);
	if ((error = fp_lookup(p, s, &fp, 1))) {
		KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, error, 0, 0, 0, 0);
		proc_fdunlock(p);
		return (error);
	}
	if (fp->f_type != DTYPE_SOCKET) {
		fp_drop(p, s, fp, 1);
		proc_fdunlock(p);
		return (ENOTSOCK);
	}

	so = (struct socket *)fp->f_data;
	if (so == NULL) {
		fp_drop(p, s, fp, 1);
		proc_fdunlock(p);
		return (EBADF);
	}

	proc_fdunlock(p);

#if CONFIG_MACF_SOCKET_SUBSET
	/*
	 * We check the state without holding the socket lock;
	 * if a race condition occurs, it would simply result
	 * in an extra call to the MAC check function.
	 */
	if (!(so->so_state & SS_ISCONNECTED) &&
	    (error = mac_socket_check_receive(kauth_cred_get(), so)) != 0)
		goto out1;
#endif /* MAC_SOCKET_SUBSET */
	if (uio_resid(uiop) < 0) {
		KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, EINVAL, 0, 0, 0, 0);
		error = EINVAL;
		goto out1;
	}

	len = uio_resid(uiop);
	error = so->so_proto->pr_usrreqs->pru_soreceive(so, &fromsa, uiop,
	    (struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
	    &mp->msg_flags);
	if (fromsa)
		AUDIT_ARG(sockaddr, vfs_context_cwd(vfs_context_current()),
		    fromsa);
	if (error) {
		if (uio_resid(uiop) != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}

	if (error)
		goto out;

	*retval = len - uio_resid(uiop);
	if (mp->msg_name) {
		socklen_t sa_len = 0;

		len = mp->msg_namelen;
		if (len <= 0 || fromsa == 0) {
			len = 0;
		} else {
#ifndef MIN
#define	MIN(a, b) ((a) > (b) ? (b) : (a))
#endif
			sa_len = fromsa->sa_len;
			len = MIN((unsigned int)len, sa_len);
			error = copyout(fromsa, mp->msg_name, (unsigned)len);
			if (error)
				goto out;
		}
		mp->msg_namelen = sa_len;
		/* return the actual, untruncated address length */
		if (namelenp &&
		    (error = copyout((caddr_t)&sa_len, namelenp,
		    sizeof (int)))) {
			goto out;
		}
	}
	if (mp->msg_control) {
		len = mp->msg_controllen;
		m = control;
		mp->msg_controllen = 0;
		ctlbuf = mp->msg_control;

		while (m && len > 0) {
			unsigned int tocopy;
			struct cmsghdr *cp = mtod(m, struct cmsghdr *);
			int cp_size = CMSG_ALIGN(cp->cmsg_len);
			int buflen = m->m_len;
			
			while (buflen > 0 && len > 0) {
				
				/* 
				 SCM_TIMESTAMP hack because  struct timeval has a 
				 * different size for 32 bits and 64 bits processes
				 */
				if (cp->cmsg_level == SOL_SOCKET &&  cp->cmsg_type == SCM_TIMESTAMP) {
					unsigned char tmp_buffer[CMSG_SPACE(sizeof(struct user64_timeval))];
					struct cmsghdr *tmp_cp = (struct cmsghdr *)tmp_buffer;
					int tmp_space;
					struct timeval *tv = (struct timeval *)CMSG_DATA(cp);
					
					tmp_cp->cmsg_level = SOL_SOCKET;
					tmp_cp->cmsg_type = SCM_TIMESTAMP;
					
					if (proc_is64bit(p)) {
						struct user64_timeval *tv64 = (struct user64_timeval *)CMSG_DATA(tmp_cp);
						
						tv64->tv_sec = tv->tv_sec;
						tv64->tv_usec = tv->tv_usec;
						
						tmp_cp->cmsg_len = CMSG_LEN(sizeof(struct user64_timeval));
						tmp_space = CMSG_SPACE(sizeof(struct user64_timeval));
					} else {
						struct user32_timeval *tv32 = (struct user32_timeval *)CMSG_DATA(tmp_cp);
						
						tv32->tv_sec = tv->tv_sec;
						tv32->tv_usec = tv->tv_usec;
						
						tmp_cp->cmsg_len = CMSG_LEN(sizeof(struct user32_timeval));
						tmp_space = CMSG_SPACE(sizeof(struct user32_timeval));
					}
					if (len >= tmp_space) {
						tocopy = tmp_space;
					} else {
						mp->msg_flags |= MSG_CTRUNC;
						tocopy = len;
					}
					error = copyout(tmp_buffer, ctlbuf, tocopy);
					if (error)
						goto out;
					
				} else {
					
					if (cp_size > buflen) {
						panic("cp_size > buflen, something wrong with alignment!");
					}
					
					if (len >= cp_size) {
						tocopy = cp_size;
					} else {
						mp->msg_flags |= MSG_CTRUNC;
						tocopy = len;
					}
					
					error = copyout((caddr_t) cp, ctlbuf,
									tocopy);
					if (error)
						goto out;
				}
				
				
				ctlbuf += tocopy;
				len -= tocopy;
				
				buflen -= cp_size;
				cp = (struct cmsghdr *) ((unsigned char *) cp + cp_size);
				cp_size = CMSG_ALIGN(cp->cmsg_len);
			}
			
			m = m->m_next;
		}
		mp->msg_controllen = ctlbuf - mp->msg_control;
	}
out:
	if (fromsa)
		FREE(fromsa, M_SONAME);
	if (control)
		m_freem(control);
	KERNEL_DEBUG(DBG_FNC_RECVIT | DBG_FUNC_END, error, 0, 0, 0, 0);
out1:
	fp_drop(p, s, fp, 0);
	return (error);
}

/*
 * Returns:	0			Success
 *		ENOMEM
 *	copyin:EFAULT
 *	recvit:???
 *	read:???			[4056224: applicable for pipes]
 *
 * Notes:	The read entry point is only called as part of support for
 *		binary backward compatability; new code should use read
 *		instead of recv or recvfrom when attempting to read data
 *		from pipes.
 *
 *		For full documentation of the return codes from recvit, see
 *		the block header for the recvit function.
 */
int
recvfrom(struct proc *p, struct recvfrom_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(recvfrom_nocancel(p, (struct recvfrom_nocancel_args *)uap, retval));
}

int
recvfrom_nocancel(struct proc *p, struct recvfrom_nocancel_args *uap, int32_t *retval)
{
	struct user_msghdr msg;
	int error;
	uio_t auio = NULL;

	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_START, 0, 0, 0, 0, 0);
	AUDIT_ARG(fd, uap->s);

	if (uap->fromlenaddr) {
		error = copyin(uap->fromlenaddr,
		    (caddr_t)&msg.msg_namelen, sizeof (msg.msg_namelen));
		if (error)
			return (error);
	} else {
		msg.msg_namelen = 0;
	}
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
	 * Temporary workaround to let send() and recv() work over
	 * a pipe for binary compatibility
	 * This will be removed in the release following Tiger
	 */
	if (error == ENOTSOCK && proc_is64bit(p) == 0) {
		struct fileproc *fp;

		if (fp_lookup(p, uap->s, &fp, 0) == 0) {
			(void) fp_drop(p, uap->s, fp, 0);

			if (fp->f_type == DTYPE_PIPE) {
				struct read_args read_uap;
				user_ssize_t read_retval;

				if (p->p_pid > last_pid_4056224) {
					last_pid_4056224 = p->p_pid;

					printf("%s[%d] uses send/recv on "
					    "a pipe\n", p->p_comm, p->p_pid);
				}

				bzero(&read_uap, sizeof (struct read_args));
				read_uap.fd = uap->s;
				read_uap.cbuf = uap->buf;
				read_uap.nbyte = uap->len;

				error = read(p, &read_uap, &read_retval);
				*retval = (int)read_retval;
			}
		}
	}
#endif /* HACK_FOR_4056224 */

	KERNEL_DEBUG(DBG_FNC_RECVFROM | DBG_FUNC_END, error, 0, 0, 0, 0);

	return (error);
}

/*
 * Returns:	0			Success
 *		EMSGSIZE
 *		ENOMEM
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	recvit:???
 *
 * Notes:	For full documentation of the return codes from recvit, see
 *		the block header for the recvit function.
 */
int
recvmsg(struct proc *p, struct recvmsg_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(recvmsg_nocancel(p, (struct recvmsg_nocancel_args *)uap, retval));
}

int
recvmsg_nocancel(struct proc *p, struct recvmsg_nocancel_args *uap, int32_t *retval)
{
	struct user32_msghdr msg32;
	struct user64_msghdr msg64;
	struct user_msghdr user_msg;
	caddr_t msghdrp;
	int	size_of_msghdr;
	user_addr_t uiov;
	int error;
	uio_t auio = NULL;
	struct user_iovec *iovp;

	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_START, 0, 0, 0, 0, 0);
	AUDIT_ARG(fd, uap->s);
	if (IS_64BIT_PROCESS(p)) {
		msghdrp = (caddr_t)&msg64;
		size_of_msghdr = sizeof (msg64);
	} else {
		msghdrp = (caddr_t)&msg32;
		size_of_msghdr = sizeof (msg32);
	}
	error = copyin(uap->msg, msghdrp, size_of_msghdr);
	if (error) {
		KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error, 0, 0, 0, 0);
		return (error);
	}

	/* only need to copy if user process is not 64-bit */
	if (IS_64BIT_PROCESS(p)) {
		user_msg.msg_flags = msg64.msg_flags;
		user_msg.msg_controllen = msg64.msg_controllen;
		user_msg.msg_control = msg64.msg_control;
		user_msg.msg_iovlen = msg64.msg_iovlen;
		user_msg.msg_iov = msg64.msg_iov;
		user_msg.msg_namelen = msg64.msg_namelen;
		user_msg.msg_name = msg64.msg_name;
	} else {
		user_msg.msg_flags = msg32.msg_flags;
		user_msg.msg_controllen = msg32.msg_controllen;
		user_msg.msg_control = msg32.msg_control;
		user_msg.msg_iovlen = msg32.msg_iovlen;
		user_msg.msg_iov = msg32.msg_iov;
		user_msg.msg_namelen = msg32.msg_namelen;
		user_msg.msg_name = msg32.msg_name;
	}

	if (user_msg.msg_iovlen <= 0 || user_msg.msg_iovlen > UIO_MAXIOV) {
		KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, EMSGSIZE,
		    0, 0, 0, 0);
		return (EMSGSIZE);
	}

	user_msg.msg_flags = uap->flags;

	/* allocate a uio large enough to hold the number of iovecs passed */
	auio = uio_create(user_msg.msg_iovlen, 0,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	    UIO_READ);
	if (auio == NULL) {
		error = ENOMEM;
		goto done;
	}

	/*
	 * get location of iovecs within the uio.  then copyin the iovecs from
	 * user space.
	 */
	iovp = uio_iovsaddr(auio);
	if (iovp == NULL) {
		error = ENOMEM;
		goto done;
	}
	uiov = user_msg.msg_iov;
	user_msg.msg_iov = CAST_USER_ADDR_T(iovp);
	error = copyin_user_iovec_array(uiov,
		IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32,
		user_msg.msg_iovlen, iovp);
	if (error)
		goto done;

	/* finish setup of uio_t */
	uio_calculateresid(auio);

	error = recvit(p, uap->s, &user_msg, auio, 0, retval);
	if (!error) {
		user_msg.msg_iov = uiov;
		if (IS_64BIT_PROCESS(p)) {
			msg64.msg_flags = user_msg.msg_flags;
			msg64.msg_controllen = user_msg.msg_controllen;
			msg64.msg_control = user_msg.msg_control;
			msg64.msg_iovlen = user_msg.msg_iovlen;
			msg64.msg_iov = user_msg.msg_iov;
			msg64.msg_namelen = user_msg.msg_namelen;
			msg64.msg_name = user_msg.msg_name;
		} else {
			msg32.msg_flags = user_msg.msg_flags;
			msg32.msg_controllen = user_msg.msg_controllen;
			msg32.msg_control = user_msg.msg_control;
			msg32.msg_iovlen = user_msg.msg_iovlen;
			msg32.msg_iov = user_msg.msg_iov;
			msg32.msg_namelen = user_msg.msg_namelen;
			msg32.msg_name = user_msg.msg_name;
		}
		error = copyout(msghdrp, uap->msg, size_of_msghdr);
	}
done:
	if (auio != NULL) {
		uio_free(auio);
	}
	KERNEL_DEBUG(DBG_FNC_RECVMSG | DBG_FUNC_END, error, 0, 0, 0, 0);
	return (error);
}

/*
 * Returns:	0			Success
 *		EBADF
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	soshutdown:EINVAL
 *	soshutdown:ENOTCONN
 *	soshutdown:EADDRNOTAVAIL[TCP]
 *	soshutdown:ENOBUFS[TCP]
 *	soshutdown:EMSGSIZE[TCP]
 *	soshutdown:EHOSTUNREACH[TCP]
 *	soshutdown:ENETUNREACH[TCP]
 *	soshutdown:ENETDOWN[TCP]
 *	soshutdown:ENOMEM[TCP]
 *	soshutdown:EACCES[TCP]
 *	soshutdown:EMSGSIZE[TCP]
 *	soshutdown:ENOBUFS[TCP]
 *	soshutdown:???[TCP]		[ignorable: mostly IPSEC/firewall/DLIL]
 *	soshutdown:???			[other protocol families]
 */
/* ARGSUSED */
int
shutdown(__unused struct proc *p, struct shutdown_args *uap,
    __unused int32_t *retval)
{
	struct socket *so;
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
	return (error);
}

/*
 * Returns:	0			Success
 *		EFAULT
 *		EINVAL
 *		EACCES			Mandatory Access Control failure
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	sosetopt:EINVAL
 *	sosetopt:ENOPROTOOPT
 *	sosetopt:ENOBUFS
 *	sosetopt:EDOM
 *	sosetopt:EFAULT
 *	sosetopt:EOPNOTSUPP[AF_UNIX]
 *	sosetopt:???
 */
/* ARGSUSED */
int
setsockopt(struct proc *p, struct setsockopt_args *uap,
    __unused int32_t *retval)
{
	struct socket *so;
	struct sockopt sopt;
	int error;

	AUDIT_ARG(fd, uap->s);
	if (uap->val == 0 && uap->valsize != 0)
		return (EFAULT);
	/* No bounds checking on size (it's unsigned) */

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
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_setsockopt(kauth_cred_get(), so,
	    &sopt)) != 0)
		goto out;
#endif /* MAC_SOCKET_SUBSET */
	error = sosetopt(so, &sopt);
out:
	file_drop(uap->s);
	return (error);
}



/*
 * Returns:	0			Success
 *		EINVAL
 *		EBADF
 *		EACCES			Mandatory Access Control failure
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	sogetopt:???
 */
int
getsockopt(struct proc *p, struct getsockopt_args  *uap,
    __unused int32_t *retval)
{
	int		error;
	socklen_t	valsize;
	struct sockopt	sopt;
	struct socket *so;

	error = file_socket(uap->s, &so);
	if (error)
		return (error);
	if (uap->val) {
		error = copyin(uap->avalsize, (caddr_t)&valsize,
		    sizeof (valsize));
		if (error)
			goto out;
		/* No bounds checking on size (it's unsigned) */
	} else {
		valsize = 0;
	}
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
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_getsockopt(kauth_cred_get(), so,
	    &sopt)) != 0)
		goto out;
#endif /* MAC_SOCKET_SUBSET */
	error = sogetopt((struct socket *)so, &sopt);
	if (error == 0) {
		valsize = sopt.sopt_valsize;
		error = copyout((caddr_t)&valsize, uap->avalsize,
		    sizeof (valsize));
	}
out:
	file_drop(uap->s);
	return (error);
}


/*
 * Get socket name.
 *
 * Returns:	0			Success
 *		EBADF
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	<pru_sockaddr>:ENOBUFS[TCP]
 *	<pru_sockaddr>:ECONNRESET[TCP]
 *	<pru_sockaddr>:EINVAL[AF_UNIX]
 *	<sf_getsockname>:???
 */
/* ARGSUSED */
int
getsockname(__unused struct proc *p, struct getsockname_args *uap,
    __unused int32_t *retval)
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	socklen_t sa_len;
	int error;

	error = file_socket(uap->fdes, &so);
	if (error)
		return (error);
	error = copyin(uap->alen, (caddr_t)&len, sizeof (socklen_t));
	if (error)
		goto out;
	if (so == NULL) {
		error = EBADF;
		goto out;
	}
	sa = 0;
	socket_lock(so, 1);
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	if (error == 0) {
		error = sflt_getsockname(so, &sa);
		if (error == EJUSTRETURN)
			error = 0;
	}
	socket_unlock(so, 1);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}

	sa_len = sa->sa_len;
	len = MIN(len, sa_len);
	error = copyout((caddr_t)sa, uap->asa, len);
	if (error)
		goto bad;
	/* return the actual, untruncated address length */
	len = sa_len;
gotnothing:
		error = copyout((caddr_t)&len, uap->alen, sizeof (socklen_t));
bad:
	if (sa)
		FREE(sa, M_SONAME);
out:
	file_drop(uap->fdes);
	return (error);
}

/*
 * Get name of peer for connected socket.
 *
 * Returns:	0			Success
 *		EBADF
 *		EINVAL
 *		ENOTCONN
 *	file_socket:ENOTSOCK
 *	file_socket:EBADF
 *	copyin:EFAULT
 *	copyout:EFAULT
 *	<pru_peeraddr>:???
 *	<sf_getpeername>:???
 */
/* ARGSUSED */
int
getpeername(__unused struct proc *p, struct getpeername_args *uap,
    __unused int32_t *retval)
{
	struct socket *so;
	struct sockaddr *sa;
	socklen_t len;
	socklen_t sa_len;
	int error;

	error = file_socket(uap->fdes, &so);
	if (error)
		return (error);
	if (so == NULL) {
		error = EBADF;
		goto out;
	}

	socket_lock(so, 1);

	if ((so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE)) ==
	    (SS_CANTRCVMORE | SS_CANTSENDMORE)) {
		/* the socket has been shutdown, no more getpeername's */
		socket_unlock(so, 1);
		error = EINVAL;
		goto out;
	}

	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING)) == 0) {
		socket_unlock(so, 1);
		error = ENOTCONN;
		goto out;
	}
	error = copyin(uap->alen, (caddr_t)&len, sizeof (socklen_t));
	if (error) {
		socket_unlock(so, 1);
		goto out;
	}
	sa = 0;
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, &sa);
	if (error == 0) {
		error = sflt_getpeername(so, &sa);
		if (error == EJUSTRETURN)
			error = 0;
	}
	socket_unlock(so, 1);
	if (error)
		goto bad;
	if (sa == 0) {
		len = 0;
		goto gotnothing;
	}
	sa_len = sa->sa_len;
	len = MIN(len, sa_len);
	error = copyout(sa, uap->asa, len);
	if (error)
		goto bad;
	/* return the actual, untruncated address length */
	len = sa_len;
gotnothing:
	error = copyout((caddr_t)&len, uap->alen, sizeof (socklen_t));
bad:
	if (sa) FREE(sa, M_SONAME);
out:
	file_drop(uap->fdes);
	return (error);
}

int
sockargs(struct mbuf **mp, user_addr_t data, int buflen, int type)
{
	struct sockaddr *sa;
	struct mbuf *m;
	int error;

	size_t alloc_buflen = (size_t)buflen;
	
	if(alloc_buflen > INT_MAX/2) 
		return (EINVAL);
#ifdef __LP64__
	/* The fd's in the buffer must expand to be pointers, thus we need twice as much space */
	if(type == MT_CONTROL)
		alloc_buflen = ((buflen - sizeof(struct cmsghdr))*2) + sizeof(struct cmsghdr);
#endif
	if (alloc_buflen > MLEN) {
		if (type == MT_SONAME && alloc_buflen <= 112)
			alloc_buflen = MLEN;		/* unix domain compat. hack */
		else if (alloc_buflen > MCLBYTES)
			return (EINVAL);
	}
	m = m_get(M_WAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	if (alloc_buflen > MLEN) {
		MCLGET(m, M_WAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
	}
	/* K64: We still copyin the original buflen because it gets expanded later
	 * and we lie about the size of the mbuf because it only affects unp_* functions
	 */
	m->m_len = buflen;
	error = copyin(data, mtod(m, caddr_t), (u_int)buflen);
	if (error) {
		(void) m_free(m);
	} else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);
			sa->sa_len = buflen;
		}
	}
	return (error);
}

/*
 * Given a user_addr_t of length len, allocate and fill out a *sa.
 *
 * Returns:	0			Success
 *		ENAMETOOLONG		Filename too long
 *		EINVAL			Invalid argument
 *		ENOMEM			Not enough space
 *		copyin:EFAULT		Bad address
 */
static int
getsockaddr(struct socket *so, struct sockaddr **namp, user_addr_t uaddr,
    size_t len, boolean_t translate_unspec)
{
	struct sockaddr *sa;
	int error;

	if (len > SOCK_MAXADDRLEN)
		return (ENAMETOOLONG);

	if (len < offsetof(struct sockaddr, sa_data[0]))
		return (EINVAL);

	MALLOC(sa, struct sockaddr *, len, M_SONAME, M_WAITOK | M_ZERO);
	if (sa == NULL) {
		return (ENOMEM);
	}
	error = copyin(uaddr, (caddr_t)sa, len);
	if (error) {
		FREE(sa, M_SONAME);
	} else {
		/*
		 * Force sa_family to AF_INET on AF_INET sockets to handle
		 * legacy applications that use AF_UNSPEC (0).  On all other
		 * sockets we leave it unchanged and let the lower layer
		 * handle it.
		 */
		if (translate_unspec && sa->sa_family == AF_UNSPEC &&
		    INP_CHECK_SOCKAF(so, AF_INET) &&
		    len == sizeof (struct sockaddr_in))
			sa->sa_family = AF_INET;

		sa->sa_len = len;
		*namp = sa;
	}
	return (error);
}

static int
getsockaddr_s(struct socket *so, struct sockaddr_storage *ss,
    user_addr_t uaddr, size_t len, boolean_t translate_unspec)
{
	int error;

	if (ss == NULL || uaddr == USER_ADDR_NULL ||
	    len < offsetof(struct sockaddr, sa_data[0]))
		return (EINVAL);

	/*
	 * sockaddr_storage size is less than SOCK_MAXADDRLEN,
	 * so the check here is inclusive.
	 */
	if (len > sizeof (*ss))
		return (ENAMETOOLONG);

	bzero(ss, sizeof (*ss));
	error = copyin(uaddr, (caddr_t)ss, len);
	if (error == 0) {
		/*
		 * Force sa_family to AF_INET on AF_INET sockets to handle
		 * legacy applications that use AF_UNSPEC (0).  On all other
		 * sockets we leave it unchanged and let the lower layer
		 * handle it.
		 */
		if (translate_unspec && ss->ss_family == AF_UNSPEC &&
		    INP_CHECK_SOCKAF(so, AF_INET) &&
		    len == sizeof (struct sockaddr_in))
			ss->ss_family = AF_INET;

		ss->ss_len = len;
	}
	return (error);
}

#if SENDFILE

SYSCTL_DECL(_kern_ipc);

#define	SFUIOBUFS 64
static int sendfileuiobufs = SFUIOBUFS;
SYSCTL_INT(_kern_ipc, OID_AUTO, sendfileuiobufs, CTLFLAG_RW | CTLFLAG_LOCKED, &sendfileuiobufs,
    0, "");

/* Macros to compute the number of mbufs needed depending on cluster size */
#define	HOWMANY_16K(n)	((((unsigned int)(n) - 1) >> (PGSHIFT + 2)) + 1)
#define	HOWMANY_4K(n)	((((unsigned int)(n) - 1) >> PGSHIFT) + 1)

/* Upper send limit in bytes (sendfileuiobufs * PAGESIZE) */
#define SENDFILE_MAX_BYTES	(sendfileuiobufs << PGSHIFT)

/* Upper send limit in the number of mbuf clusters */
#define	SENDFILE_MAX_16K	HOWMANY_16K(SENDFILE_MAX_BYTES)
#define	SENDFILE_MAX_4K		HOWMANY_4K(SENDFILE_MAX_BYTES)

size_t mbuf_pkt_maxlen(mbuf_t m);

__private_extern__ size_t
mbuf_pkt_maxlen(mbuf_t m)
{
	size_t maxlen = 0;

	while (m) {
		maxlen += mbuf_maxlen(m);
		m = mbuf_next(m);
	}
	return (maxlen);
}

static void
alloc_sendpkt(int how, size_t pktlen, unsigned int *maxchunks,
    struct mbuf **m, boolean_t jumbocl)
{
	unsigned int needed;

	if (pktlen == 0)
		panic("%s: pktlen (%ld) must be non-zero\n", __func__, pktlen);

	/*
	 * Try to allocate for the whole thing.  Since we want full control
	 * over the buffer size and be able to accept partial result, we can't
	 * use mbuf_allocpacket().  The logic below is similar to sosend().
	 */
	*m = NULL;
	if (pktlen > MBIGCLBYTES && jumbocl) {
		needed = MIN(SENDFILE_MAX_16K, HOWMANY_16K(pktlen));
		*m = m_getpackets_internal(&needed, 1, how, 0, M16KCLBYTES);
	}
	if (*m == NULL) {
		needed = MIN(SENDFILE_MAX_4K, HOWMANY_4K(pktlen));
		*m = m_getpackets_internal(&needed, 1, how, 0, MBIGCLBYTES);
	}

	/*
	 * Our previous attempt(s) at allocation had failed; the system
	 * may be short on mbufs, and we want to block until they are
	 * available.  This time, ask just for 1 mbuf and don't return
	 * until we get it.
	 */
	if (*m == NULL) {
		needed = 1;
		*m = m_getpackets_internal(&needed, 1, M_WAIT, 1, MBIGCLBYTES);
	}
	if (*m == NULL)
		panic("%s: blocking allocation returned NULL\n", __func__);

	*maxchunks = needed;
}

/*
 * sendfile(2).
 * int sendfile(int fd, int s, off_t offset, off_t *nbytes,
 *	 struct sf_hdtr *hdtr, int flags)
 *
 * Send a file specified by 'fd' and starting at 'offset' to a socket
 * specified by 's'. Send only '*nbytes' of the file or until EOF if
 * *nbytes == 0. Optionally add a header and/or trailer to the socket
 * output. If specified, write the total number of bytes sent into *nbytes.
 */
int
sendfile(struct proc *p, struct sendfile_args *uap, __unused int *retval)
{
	struct fileproc *fp;
	struct vnode *vp;
	struct socket *so;
	struct writev_nocancel_args nuap;
	user_ssize_t writev_retval;
	struct user_sf_hdtr user_hdtr;
	struct user32_sf_hdtr user32_hdtr;
	struct user64_sf_hdtr user64_hdtr;
	off_t off, xfsize;
	off_t nbytes = 0, sbytes = 0;
	int error = 0;
	size_t sizeof_hdtr;
	off_t file_size;
	struct vfs_context context = *vfs_context_current();

	KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE | DBG_FUNC_START), uap->s,
	    0, 0, 0, 0);

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(value32, uap->s);

	/*
	 * Do argument checking. Must be a regular file in, stream
	 * type and connected socket out, positive offset.
	 */
	if ((error = fp_getfvp(p, uap->fd, &fp, &vp))) {
		goto done;
	}
	if ((fp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto done1;
	}
	if (vnode_isreg(vp) == 0) {
		error = ENOTSUP;
		goto done1;
	}
	error = file_socket(uap->s, &so);
	if (error) {
		goto done1;
	}
	if (so == NULL) {
		error = EBADF;
		goto done2;
	}
	if (so->so_type != SOCK_STREAM) {
		error = EINVAL;
		goto done2;
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto done2;
	}
	if (uap->offset < 0) {
		error = EINVAL;
		goto done2;
	}
	if (uap->nbytes == USER_ADDR_NULL) {
		error = EINVAL;
		goto done2;
	}
	if (uap->flags != 0) {
		error = EINVAL;
		goto done2;
	}

	context.vc_ucred = fp->f_fglob->fg_cred;

#if CONFIG_MACF_SOCKET_SUBSET
	/* JMM - fetch connected sockaddr? */
	error = mac_socket_check_send(context.vc_ucred, so, NULL);
	if (error)
		goto done2;
#endif

	/*
	 * Get number of bytes to send
	 * Should it applies to size of header and trailer?
	 * JMM - error handling?
	 */
	copyin(uap->nbytes, &nbytes, sizeof (off_t));

	/*
	 * If specified, get the pointer to the sf_hdtr struct for
	 * any headers/trailers.
	 */
	if (uap->hdtr != USER_ADDR_NULL) {
		caddr_t hdtrp;

		bzero(&user_hdtr, sizeof (user_hdtr));
		if (IS_64BIT_PROCESS(p)) {
			hdtrp = (caddr_t)&user64_hdtr;
			sizeof_hdtr = sizeof (user64_hdtr);
		} else {
			hdtrp = (caddr_t)&user32_hdtr;
			sizeof_hdtr = sizeof (user32_hdtr);
		}
		error = copyin(uap->hdtr, hdtrp, sizeof_hdtr);
		if (error)
			goto done2;
		if (IS_64BIT_PROCESS(p)) {
			user_hdtr.headers = user64_hdtr.headers;
			user_hdtr.hdr_cnt = user64_hdtr.hdr_cnt;
			user_hdtr.trailers = user64_hdtr.trailers;
			user_hdtr.trl_cnt = user64_hdtr.trl_cnt;
		} else {
			user_hdtr.headers = user32_hdtr.headers;
			user_hdtr.hdr_cnt = user32_hdtr.hdr_cnt;
			user_hdtr.trailers = user32_hdtr.trailers;
			user_hdtr.trl_cnt = user32_hdtr.trl_cnt;
		}

		/*
		 * Send any headers. Wimp out and use writev(2).
		 */
		if (user_hdtr.headers != USER_ADDR_NULL) {
			bzero(&nuap, sizeof (struct writev_args));
			nuap.fd = uap->s;
			nuap.iovp = user_hdtr.headers;
			nuap.iovcnt = user_hdtr.hdr_cnt;
			error = writev_nocancel(p, &nuap, &writev_retval);
			if (error)
				goto done2;
			sbytes += writev_retval;
		}
	}

	/*
	 * Get the file size for 2 reasons:
	 *  1. We don't want to allocate more mbufs than necessary
	 *  2. We don't want to read past the end of file
	 */
	if ((error = vnode_size(vp, &file_size, vfs_context_current())) != 0)
		goto done2;

	/*
	 * Simply read file data into a chain of mbufs that used with scatter
	 * gather reads. We're not (yet?) setup to use zero copy external
	 * mbufs that point to the file pages.
	 */
	socket_lock(so, 1);
	error = sblock(&so->so_snd, M_WAIT);
	if (error) {
		socket_unlock(so, 1);
		goto done2;
	}
	for (off = uap->offset; ; off += xfsize, sbytes += xfsize) {
		mbuf_t	m0 = NULL, m;
		unsigned int	nbufs = sendfileuiobufs, i;
		uio_t	auio;
		char	uio_buf[UIO_SIZEOF(sendfileuiobufs)]; /* 1 KB !!! */
		size_t	uiolen;
		user_ssize_t	rlen;
		off_t	pgoff;
		size_t	pktlen;
		boolean_t jumbocl;

		/*
		 * Calculate the amount to transfer.
		 * Align to round number of pages.
		 * Not to exceed send socket buffer,
		 * the EOF, or the passed in nbytes.
		 */
		xfsize = sbspace(&so->so_snd);

		if (xfsize <= 0) {
			if (so->so_state & SS_CANTSENDMORE) {
				error = EPIPE;
				goto done3;
			} else if ((so->so_state & SS_NBIO)) {
				error = EAGAIN;
				goto done3;
			} else {
				xfsize = PAGE_SIZE;
			}
		}

		if (xfsize > SENDFILE_MAX_BYTES)
			xfsize = SENDFILE_MAX_BYTES;
		else if (xfsize > PAGE_SIZE)
			xfsize = trunc_page(xfsize);
		pgoff = off & PAGE_MASK_64;
		if (pgoff > 0 && PAGE_SIZE - pgoff < xfsize)
			xfsize = PAGE_SIZE_64 - pgoff;
		if (nbytes && xfsize > (nbytes - sbytes))
			xfsize = nbytes - sbytes;
		if (xfsize <= 0)
			break;
		if (off + xfsize > file_size)
			xfsize = file_size - off;
		if (xfsize <= 0)
			break;

		/*
		 * Attempt to use larger than system page-size clusters for
		 * large writes only if there is a jumbo cluster pool and
		 * if the socket is marked accordingly.
		 */
		jumbocl = sosendjcl && njcl > 0 &&
		    ((so->so_flags & SOF_MULTIPAGES) || sosendjcl_ignore_capab);

		socket_unlock(so, 0);
		alloc_sendpkt(M_WAIT, xfsize, &nbufs, &m0, jumbocl);
		pktlen = mbuf_pkt_maxlen(m0);
		if (pktlen < (size_t)xfsize)
			xfsize = pktlen;

		auio = uio_createwithbuffer(nbufs, off, UIO_SYSSPACE,
		    UIO_READ, &uio_buf[0], sizeof (uio_buf));
		if (auio == NULL) {
			//printf("sendfile: uio_createwithbuffer failed\n");
			mbuf_freem(m0);
			error = ENXIO;
			socket_lock(so, 0);
			goto done3;
		}

		for (i = 0, m = m0, uiolen = 0;
		    i < nbufs && m != NULL && uiolen < (size_t)xfsize;
		    i++, m = mbuf_next(m)) {
			size_t mlen = mbuf_maxlen(m);

			if (mlen + uiolen > (size_t)xfsize)
				mlen = xfsize - uiolen;
			mbuf_setlen(m, mlen);
			uio_addiov(auio, CAST_USER_ADDR_T(mbuf_datastart(m)),
			    mlen);
			uiolen += mlen;
		}

		if (xfsize != uio_resid(auio))
			printf("sendfile: xfsize: %lld != uio_resid(auio): "
				"%lld\n", xfsize, (long long)uio_resid(auio));

		KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_READ | DBG_FUNC_START),
		    uap->s, (unsigned int)((xfsize >> 32) & 0x0ffffffff),
		    (unsigned int)(xfsize & 0x0ffffffff), 0, 0);
		error = fo_read(fp, auio, FOF_OFFSET, &context);
		socket_lock(so, 0);
		if (error != 0) {
			if (uio_resid(auio) != xfsize && (error == ERESTART ||
			    error == EINTR || error == EWOULDBLOCK)) {
				error = 0;
			} else {
				mbuf_freem(m0);
				goto done3;
			}
		}
		xfsize -= uio_resid(auio);
		KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_READ | DBG_FUNC_END),
		    uap->s, (unsigned int)((xfsize >> 32) & 0x0ffffffff),
		    (unsigned int)(xfsize & 0x0ffffffff), 0, 0);

		if (xfsize == 0) {
			//printf("sendfile: fo_read 0 bytes, EOF\n");
			break;
		}
		if (xfsize + off > file_size)
			printf("sendfile: xfsize: %lld + off: %lld > file_size:"
			    "%lld\n", xfsize, off, file_size);
		for (i = 0, m = m0, rlen = 0;
		    i < nbufs && m != NULL && rlen < xfsize;
		    i++, m = mbuf_next(m)) {
			size_t mlen = mbuf_maxlen(m);

			if (rlen + mlen > (size_t)xfsize)
				mlen = xfsize - rlen;
			mbuf_setlen(m, mlen);

			rlen += mlen;
		}
		mbuf_pkthdr_setlen(m0, xfsize);

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
			m_freem(m0);
			goto done3;
		}
		/*
		 * Wait for socket space to become available. We do this just
		 * after checking the connection state above in order to avoid
		 * a race condition with sbwait().
		 */
		if (sbspace(&so->so_snd) < (long)so->so_snd.sb_lowat) {
			if (so->so_state & SS_NBIO) {
				m_freem(m0);
				error = EAGAIN;
				goto done3;
			}
			KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_WAIT |
			    DBG_FUNC_START), uap->s, 0, 0, 0, 0);
			error = sbwait(&so->so_snd);
			KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_WAIT|
			    DBG_FUNC_END), uap->s, 0, 0, 0, 0);
			/*
			 * An error from sbwait usually indicates that we've
			 * been interrupted by a signal. If we've sent anything
			 * then return bytes sent, otherwise return the error.
			 */
			if (error) {
				m_freem(m0);
				goto done3;
			}
			goto retry_space;
		}
		
		struct mbuf *control = NULL;
		{
			/*
			 * Socket filter processing
			 */

			error = sflt_data_out(so, NULL, &m0, &control, 0);
			if (error) {
				if (error == EJUSTRETURN) {
					error = 0;
					continue;
				}
				goto done3;
			}
			/*
			 * End Socket filter processing
			 */
		}
		KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_SEND | DBG_FUNC_START),
		    uap->s, 0, 0, 0, 0);
		error = (*so->so_proto->pr_usrreqs->pru_send)(so, 0, m0,
		    0, control, p);
		KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE_SEND | DBG_FUNC_START),
		    uap->s, 0, 0, 0, 0);
		if (error) {
			goto done3;
		}
	}
	sbunlock(&so->so_snd, 0);	/* will unlock socket */
	/*
	 * Send trailers. Wimp out and use writev(2).
	 */
	if (uap->hdtr != USER_ADDR_NULL &&
	    user_hdtr.trailers != USER_ADDR_NULL) {
		bzero(&nuap, sizeof (struct writev_args));
		nuap.fd = uap->s;
		nuap.iovp = user_hdtr.trailers;
		nuap.iovcnt = user_hdtr.trl_cnt;
		error = writev_nocancel(p, &nuap, &writev_retval);
		if (error)
			goto done2;
		sbytes += writev_retval;
	}
done2:
	file_drop(uap->s);
done1:
	file_drop(uap->fd);
done:
	if (uap->nbytes != USER_ADDR_NULL) {
		/* XXX this appears bogus for some early failure conditions */
		copyout(&sbytes, uap->nbytes, sizeof (off_t));
	}
	KERNEL_DEBUG_CONSTANT((DBG_FNC_SENDFILE | DBG_FUNC_END), uap->s,
	    (unsigned int)((sbytes >> 32) & 0x0ffffffff),
	    (unsigned int)(sbytes & 0x0ffffffff), error, 0);
	return (error);
done3:
	sbunlock(&so->so_snd, 0);	/* will unlock socket */
	goto done2;
}


#endif /* SENDFILE */
