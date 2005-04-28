/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	From: @(#)uipc_usrreq.c	8.3 (Berkeley) 1/4/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>		/* XXX must be before <sys/file.h> */
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/unpcb.h>
#include <sys/vnode_internal.h>
#include <sys/kdebug.h>

#include <kern/zalloc.h>
#include <kern/locks.h>

#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
struct	zone *unp_zone;
static	unp_gen_t unp_gencnt;
static	u_int unp_count;
static	lck_mtx_t 		*unp_mutex;

extern lck_mtx_t * uipc_lock;
static	struct unp_head unp_shead, unp_dhead;

/*
 * Unix communications domain.
 *
 * TODO:
 *	SEQPACKET, RDM
 *	rethink name space problems
 *	need a proper out-of-band
 *	lock pushdown
 */
static struct	sockaddr sun_noname = { sizeof(sun_noname), AF_LOCAL, { 0 } };
static ino_t	unp_ino;		/* prototype for fake inode numbers */

static int     unp_attach(struct socket *);
static void    unp_detach(struct unpcb *);
static int     unp_bind(struct unpcb *,struct sockaddr *, struct proc *);
static int     unp_connect(struct socket *,struct sockaddr *, struct proc *);
static void    unp_disconnect(struct unpcb *);
static void    unp_shutdown(struct unpcb *);
static void    unp_drop(struct unpcb *, int);
static void    unp_gc(void);
static void    unp_scan(struct mbuf *, void (*)(struct fileglob *));
static void    unp_mark(struct fileglob *);
static void    unp_discard(struct fileglob *);
static void    unp_discard_fdlocked(struct fileglob *, struct proc *);
static int     unp_internalize(struct mbuf *, struct proc *);
static int     unp_listen(struct unpcb *, struct proc *);


static int
uipc_abort(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	unp_drop(unp, ECONNABORTED);
	unp_detach(unp);
	sofree(so);
	return 0;
}

static int
uipc_accept(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;

	/*
	 * Pass back name of connected socket,
	 * if it was bound and we are still connected
	 * (our peer may have closed already!).
	 */
	if (unp->unp_conn && unp->unp_conn->unp_addr) {
		*nam = dup_sockaddr((struct sockaddr *)unp->unp_conn->unp_addr,
				    1);
	} else {
		*nam = dup_sockaddr((struct sockaddr *)&sun_noname, 1);
	}
	return 0;
}

static int
uipc_attach(struct socket *so, __unused int proto, __unused struct proc *p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp != 0)
		return EISCONN;
	return unp_attach(so);
}

static int
uipc_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;

	return unp_bind(unp, nam, p);
}

static int
uipc_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	return unp_connect(so, nam, p);
}

static int
uipc_connect2(struct socket *so1, struct socket *so2)
{
	struct unpcb *unp = sotounpcb(so1);

	if (unp == 0)
		return EINVAL;

	return unp_connect2(so1, so2);
}

/* control is EOPNOTSUPP */

static int
uipc_detach(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;

	unp_detach(unp);
	return 0;
}

static int
uipc_disconnect(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	unp_disconnect(unp);
	return 0;
}

static int
uipc_listen(struct socket *so, __unused struct proc *p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0 || unp->unp_vnode == 0)
		return EINVAL;
	return unp_listen(unp, p);
}

static int
uipc_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	if (unp->unp_conn && unp->unp_conn->unp_addr)
		*nam = dup_sockaddr((struct sockaddr *)unp->unp_conn->unp_addr,
				    1);
	return 0;
}

static int
uipc_rcvd(struct socket *so, __unused int flags)
{
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;

	if (unp == 0)
		return EINVAL;
	switch (so->so_type) {
	case SOCK_DGRAM:
		panic("uipc_rcvd DGRAM?");
		/*NOTREACHED*/

	case SOCK_STREAM:
#define	rcv (&so->so_rcv)
#define snd (&so2->so_snd)
		if (unp->unp_conn == 0)
			break;
		so2 = unp->unp_conn->unp_socket;
		/*
		 * Adjust backpressure on sender
		 * and wakeup any waiting to write.
		 */
		snd->sb_mbmax += unp->unp_mbcnt - rcv->sb_mbcnt;
		unp->unp_mbcnt = rcv->sb_mbcnt;
		snd->sb_hiwat += unp->unp_cc - rcv->sb_cc;
		unp->unp_cc = rcv->sb_cc;
		sowwakeup(so2);
#undef snd
#undef rcv
		break;

	default:
		panic("uipc_rcvd unknown socktype");
	}
	return 0;
}

/* pru_rcvoob is EOPNOTSUPP */

static int
uipc_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	  struct mbuf *control, struct proc *p)
{
	int error = 0;
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;

	if (unp == 0) {
		error = EINVAL;
		goto release;
	}
	if (flags & PRUS_OOB) {
		error = EOPNOTSUPP;
		goto release;
	}

	if (control && (error = unp_internalize(control, p)))
		goto release;

	switch (so->so_type) {
	case SOCK_DGRAM: 
	{
		struct sockaddr *from;

		if (nam) {
			if (unp->unp_conn) {
				error = EISCONN;
				break;
			}
			error = unp_connect(so, nam, p);
			if (error)
				break;
		} else {
			if (unp->unp_conn == 0) {
				error = ENOTCONN;
				break;
			}
		}
		so2 = unp->unp_conn->unp_socket;
		if (unp->unp_addr)
			from = (struct sockaddr *)unp->unp_addr;
		else
			from = &sun_noname;
		if (sbappendaddr(&so2->so_rcv, from, m, control, &error)) {
			sorwakeup(so2);
		}
		m = 0;
		control = 0;
		if (nam)
			unp_disconnect(unp);
		break;
	}

	case SOCK_STREAM: {
		int didreceive = 0;
#define	rcv (&so2->so_rcv)
#define	snd (&so->so_snd)
		/* Connect if not connected yet. */
		/*
		 * Note: A better implementation would complain
		 * if not equal to the peer's address.
		 */
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			if (nam) {
				error = unp_connect(so, nam, p);
				if (error)
					break;	/* XXX */
			} else {
				error = ENOTCONN;
				break;
			}
		}

		if (so->so_state & SS_CANTSENDMORE) {
			error = EPIPE;
			break;
		}
		if (unp->unp_conn == 0)
			panic("uipc_send connected but no connection?");
		so2 = unp->unp_conn->unp_socket;
		/*
		 * Send to paired receive port, and then reduce
		 * send buffer hiwater marks to maintain backpressure.
		 * Wake up readers.
		 */
		if ((control && sbappendcontrol(rcv, m, control, NULL)) ||
			sbappend(rcv, m)) {
			didreceive = 1;
		}
		snd->sb_mbmax -=
			rcv->sb_mbcnt - unp->unp_conn->unp_mbcnt;
		unp->unp_conn->unp_mbcnt = rcv->sb_mbcnt;
		snd->sb_hiwat -= rcv->sb_cc - unp->unp_conn->unp_cc;
		unp->unp_conn->unp_cc = rcv->sb_cc;
		if (didreceive)
			sorwakeup(so2);
		m = 0;
		control = 0;
#undef snd
#undef rcv
		}
		break;

	default:
		panic("uipc_send unknown socktype");
	}

	/*
	 * SEND_EOF is equivalent to a SEND followed by
	 * a SHUTDOWN.
	 */
	if (flags & PRUS_EOF) {
		socantsendmore(so);
		unp_shutdown(unp);
	}

	if (control && error != 0)
		unp_dispose(control);

release:
	if (control)
		m_freem(control);
	if (m)
		m_freem(m);
	return error;
}

static int
uipc_sense(struct socket *so, struct stat *sb)
{
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;

	if (unp == 0)
		return EINVAL;
	sb->st_blksize = so->so_snd.sb_hiwat;
	if (so->so_type == SOCK_STREAM && unp->unp_conn != 0) {
		so2 = unp->unp_conn->unp_socket;
		sb->st_blksize += so2->so_rcv.sb_cc;
	}
	sb->st_dev = NODEV;
	if (unp->unp_ino == 0)
		unp->unp_ino = unp_ino++;
	sb->st_ino = unp->unp_ino;
	return (0);
}

static int
uipc_shutdown(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	socantsendmore(so);
	unp_shutdown(unp);
	return 0;
}

static int
uipc_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return EINVAL;
	if (unp->unp_addr)
		*nam = dup_sockaddr((struct sockaddr *)unp->unp_addr, 1);
	return 0;
}

struct pr_usrreqs uipc_usrreqs = {
	uipc_abort, uipc_accept, uipc_attach, uipc_bind, uipc_connect,
	uipc_connect2, pru_control_notsupp, uipc_detach, uipc_disconnect,
	uipc_listen, uipc_peeraddr, uipc_rcvd, pru_rcvoob_notsupp,
	uipc_send, uipc_sense, uipc_shutdown, uipc_sockaddr,
	sosend, soreceive, pru_sopoll_notsupp
};

int
uipc_ctloutput(
	struct socket *so,
	struct sockopt *sopt)
{
	struct unpcb *unp = sotounpcb(so);
	int error;

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case LOCAL_PEERCRED:
			if (unp->unp_flags & UNP_HAVEPC)
				error = sooptcopyout(sopt, &unp->unp_peercred,
				    sizeof(unp->unp_peercred));
			else {
				if (so->so_type == SOCK_STREAM)
					error = ENOTCONN;
				else
					error = EINVAL;
			}
			break;
		default:
			error = EOPNOTSUPP;
			break;
		}
		break;
	case SOPT_SET:
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}
	
/*
 * Both send and receive buffers are allocated PIPSIZ bytes of buffering
 * for stream sockets, although the total for sender and receiver is
 * actually only PIPSIZ.
 * Datagram sockets really use the sendspace as the maximum datagram size,
 * and don't really want to reserve the sendspace.  Their recvspace should
 * be large enough for at least one max-size datagram plus address.
 */
#ifndef PIPSIZ
#define	PIPSIZ	8192
#endif
static u_long	unpst_sendspace = PIPSIZ;
static u_long	unpst_recvspace = PIPSIZ;
static u_long	unpdg_sendspace = 2*1024;	/* really max datagram size */
static u_long	unpdg_recvspace = 4*1024;

static int	unp_rights;			/* file descriptors in flight */

SYSCTL_DECL(_net_local_stream);
SYSCTL_INT(_net_local_stream, OID_AUTO, sendspace, CTLFLAG_RW, 
	   &unpst_sendspace, 0, "");
SYSCTL_INT(_net_local_stream, OID_AUTO, recvspace, CTLFLAG_RW,
	   &unpst_recvspace, 0, "");
SYSCTL_DECL(_net_local_dgram);
SYSCTL_INT(_net_local_dgram, OID_AUTO, maxdgram, CTLFLAG_RW,
	   &unpdg_sendspace, 0, "");
SYSCTL_INT(_net_local_dgram, OID_AUTO, recvspace, CTLFLAG_RW,
	   &unpdg_recvspace, 0, "");
SYSCTL_DECL(_net_local);
SYSCTL_INT(_net_local, OID_AUTO, inflight, CTLFLAG_RD, &unp_rights, 0, "");

static int
unp_attach(struct socket *so)
{
	struct unpcb *unp;
	int error = 0;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		switch (so->so_type) {

		case SOCK_STREAM:
			error = soreserve(so, unpst_sendspace, unpst_recvspace);
			break;

		case SOCK_DGRAM:
			error = soreserve(so, unpdg_sendspace, unpdg_recvspace);
			break;

		default:
			panic("unp_attach");
		}
		if (error)
			return (error);
	}
	unp = (struct unpcb*)zalloc(unp_zone);
	if (unp == NULL)
		return (ENOBUFS);
	bzero(unp, sizeof *unp);
	lck_mtx_lock(unp_mutex);
	LIST_INIT(&unp->unp_refs);
	unp->unp_socket = so;
	unp->unp_gencnt = ++unp_gencnt;
	unp_count++;
	LIST_INSERT_HEAD(so->so_type == SOCK_DGRAM ? &unp_dhead
			 : &unp_shead, unp, unp_link);
	so->so_pcb = (caddr_t)unp;
	lck_mtx_unlock(unp_mutex);
	return (0);
}

static void
unp_detach(struct unpcb *unp)
{
	lck_mtx_assert(unp_mutex, LCK_MTX_ASSERT_OWNED);
	LIST_REMOVE(unp, unp_link);
	unp->unp_gencnt = ++unp_gencnt;
	--unp_count;
	if (unp->unp_vnode) {
		struct vnode *tvp = unp->unp_vnode;
		unp->unp_vnode->v_socket = 0;
		unp->unp_vnode = 0;
		vnode_rele(tvp);		/* drop the usecount */
	}
	if (unp->unp_conn)
		unp_disconnect(unp);
	while (unp->unp_refs.lh_first)
		unp_drop(unp->unp_refs.lh_first, ECONNRESET);
	soisdisconnected(unp->unp_socket);
	unp->unp_socket->so_flags |= SOF_PCBCLEARING; /* makes sure we're getting dealloced */
	unp->unp_socket->so_pcb = 0;
	if (unp_rights) {
		/*
		 * Normally the receive buffer is flushed later,
		 * in sofree, but if our receive buffer holds references
		 * to descriptors that are now garbage, we will dispose
		 * of those descriptor references after the garbage collector
		 * gets them (resulting in a "panic: closef: count < 0").
		 */
		sorflush(unp->unp_socket);
		unp_gc();
	}
	if (unp->unp_addr)
		FREE(unp->unp_addr, M_SONAME);
	zfree(unp_zone, unp);
}

static int
unp_bind(
	struct unpcb *unp,
	struct sockaddr *nam,
	struct proc *p)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vnode *vp, *dvp;
	struct vnode_attr va;
	struct vfs_context context;
	int error, namelen;
	struct nameidata nd;
	char buf[SOCK_MAXADDRLEN];

	context.vc_proc = p;
	context.vc_ucred = p->p_ucred;	/* XXX kauth_cred_get() ??? proxy */

	if (unp->unp_vnode != NULL)
		return (EINVAL);
	namelen = soun->sun_len - offsetof(struct sockaddr_un, sun_path);
	if (namelen <= 0)
		return EINVAL;
	strncpy(buf, soun->sun_path, namelen);
	buf[namelen] = 0;	/* null-terminate the string */
	NDINIT(&nd, CREATE, FOLLOW | LOCKPARENT, UIO_SYSSPACE32,
	    CAST_USER_ADDR_T(buf), &context);
/* SHOULD BE ABLE TO ADOPT EXISTING AND wakeup() ALA FIFO's */
	error = namei(&nd);
	if (error) {
		return (error);
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp != NULL) {
	        /*
		 * need to do this before the vnode_put of dvp
		 * since we may have to release an fs_nodelock
		 */
		nameidone(&nd);

		vnode_put(dvp);
		vnode_put(vp);

		return (EADDRINUSE);
	}

	/* authorize before creating */
	error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context);

	if (!error) {
		VATTR_INIT(&va);
		VATTR_SET(&va, va_type, VSOCK);
		VATTR_SET(&va, va_mode, (ACCESSPERMS & ~p->p_fd->fd_cmask));

		/* create the socket */
		error = vn_create(dvp, &vp, &nd.ni_cnd, &va, 0, &context);
	}
	
	nameidone(&nd);
	vnode_put(dvp);

	if (error) {
		return (error);
	}
	vnode_ref(vp);	/* gain a longterm reference */
	vp->v_socket = unp->unp_socket;
	unp->unp_vnode = vp;
	unp->unp_addr = (struct sockaddr_un *)dup_sockaddr(nam, 1);
	vnode_put(vp);		/* drop the iocount */

	return (0);
}

static int
unp_connect(
	struct socket *so,
	struct sockaddr *nam,
	struct proc *p)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vnode *vp;
	struct socket *so2, *so3;
	struct unpcb *unp, *unp2, *unp3;
	struct vfs_context context;
	int error, len;
	struct nameidata nd;
	char buf[SOCK_MAXADDRLEN];

	context.vc_proc = p;
	context.vc_ucred = p->p_ucred;	/* XXX kauth_cred_get() ??? proxy */

	len = nam->sa_len - offsetof(struct sockaddr_un, sun_path);
	if (len <= 0)
		return EINVAL;
	strncpy(buf, soun->sun_path, len);
	buf[len] = 0;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32, CAST_USER_ADDR_T(buf), &context);
	error = namei(&nd);
	if (error) {
		return (error);
	}
	nameidone(&nd);
	vp = nd.ni_vp;
	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		goto bad;
	}

	error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, &context);
	if (error)
		goto bad;
	so2 = vp->v_socket;
	if (so2 == 0) {
		error = ECONNREFUSED;
		goto bad;
	}

	/* make sure the socket can't go away while we're connecting */
	so2->so_usecount++;

	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		goto bad;
	}
	
	/*
	 * Check if socket was connected while we were trying to
	 * acquire the funnel.
	 * XXX - probably shouldn't return an error for SOCK_DGRAM
	 */
	if ((so->so_state & SS_ISCONNECTED) != 0) {
		error = EISCONN;
		goto bad;
	}
	
	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		if ((so2->so_options & SO_ACCEPTCONN) == 0 ||
		    (so3 = sonewconn(so2, 0, nam)) == 0) {
			error = ECONNREFUSED;
			goto bad;
		}
		unp = sotounpcb(so);
		unp2 = sotounpcb(so2);
		unp3 = sotounpcb(so3);
		if (unp2->unp_addr)
			unp3->unp_addr = (struct sockaddr_un *)
				dup_sockaddr((struct sockaddr *)
					     unp2->unp_addr, 1);

		/*
		 * unp_peercred management:
		 *
		 * The connecter's (client's) credentials are copied
		 * from its process structure at the time of connect()
		 * (which is now).
		 */
		cru2x(p->p_ucred, &unp3->unp_peercred);
		unp3->unp_flags |= UNP_HAVEPC;
		/*
		 * The receiver's (server's) credentials are copied
		 * from the unp_peercred member of socket on which the
		 * former called listen(); unp_listen() cached that
		 * process's credentials at that time so we can use
		 * them now.
		 */
		KASSERT(unp2->unp_flags & UNP_HAVEPCCACHED,
		    ("unp_connect: listener without cached peercred"));
		memcpy(&unp->unp_peercred, &unp2->unp_peercred,
		    sizeof(unp->unp_peercred));
		unp->unp_flags |= UNP_HAVEPC;

		so2->so_usecount--; /* drop reference taken on so2 */
		so2 = so3;
		so3->so_usecount++; /* make sure we keep it around */
	}
	error = unp_connect2(so, so2);
bad:
	if (so2 != NULL)
		so2->so_usecount--; /* release count on socket */
	vnode_put(vp);
	return (error);
}

int
unp_connect2(
	struct socket *so,
	struct socket *so2)
{
	struct unpcb *unp = sotounpcb(so);
	struct unpcb *unp2;

	if (so2->so_type != so->so_type)
		return (EPROTOTYPE);
	unp2 = sotounpcb(so2);

	/* Verify both sockets are still opened */
	if (unp == 0 || unp2 == 0)
		return (EINVAL);

	unp->unp_conn = unp2;
	switch (so->so_type) {

	case SOCK_DGRAM:
		LIST_INSERT_HEAD(&unp2->unp_refs, unp, unp_reflink);
		soisconnected(so);
		break;

	case SOCK_STREAM:
                /* This takes care of socketpair */
                if (!(unp->unp_flags & UNP_HAVEPC) && !(unp2->unp_flags & UNP_HAVEPC)) {
                        cru2x(kauth_cred_get(), &unp->unp_peercred);
                        unp->unp_flags |= UNP_HAVEPC;
                        
                        cru2x(kauth_cred_get(), &unp2->unp_peercred);
                        unp2->unp_flags |= UNP_HAVEPC;
                }
		unp2->unp_conn = unp;
		soisconnected(so);
		soisconnected(so2);
		break;

	default:
		panic("unp_connect2");
	}
	return (0);
}

static void
unp_disconnect(struct unpcb *unp)
{
	struct unpcb *unp2 = unp->unp_conn;

	if (unp2 == 0)
		return;
	lck_mtx_assert(unp_mutex, LCK_MTX_ASSERT_OWNED);
	unp->unp_conn = 0;
	switch (unp->unp_socket->so_type) {

	case SOCK_DGRAM:
		LIST_REMOVE(unp, unp_reflink);
		unp->unp_socket->so_state &= ~SS_ISCONNECTED;
		break;

	case SOCK_STREAM:
		soisdisconnected(unp->unp_socket);
		unp2->unp_conn = 0;
		soisdisconnected(unp2->unp_socket);
		break;
	}
}

#ifdef notdef
void
unp_abort(struct unpcb *unp)
{

	unp_detach(unp);
}
#endif

static int
unp_pcblist SYSCTL_HANDLER_ARGS
{
	int error, i, n;
	struct unpcb *unp, **unp_list;
	unp_gen_t gencnt;
	struct xunpgen xug;
	struct unp_head *head;

	lck_mtx_lock(unp_mutex);
	head = ((intptr_t)arg1 == SOCK_DGRAM ? &unp_dhead : &unp_shead);

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		n = unp_count;
		req->oldidx = 2 * (sizeof xug)
			+ (n + n/8) * sizeof(struct xunpcb);
		lck_mtx_unlock(unp_mutex);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_mtx_unlock(unp_mutex);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = unp_gencnt;
	n = unp_count;

	xug.xug_len = sizeof xug;
	xug.xug_count = n;
	xug.xug_gen = gencnt;
	xug.xug_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xug, sizeof xug);
	if (error) {
		lck_mtx_unlock(unp_mutex);
		return error;
	}

	/*
	 * We are done if there is no pcb
	 */
	if (n == 0)  {
	    lck_mtx_unlock(unp_mutex);
	    return 0;
	}

	MALLOC(unp_list, struct unpcb **, n * sizeof *unp_list, M_TEMP, M_WAITOK);
	if (unp_list == 0) {
		lck_mtx_unlock(unp_mutex);
		return ENOMEM;
	}
	
	for (unp = head->lh_first, i = 0; unp && i < n;
	     unp = unp->unp_link.le_next) {
		if (unp->unp_gencnt <= gencnt)
			unp_list[i++] = unp;
	}
	n = i;			/* in case we lost some during malloc */

	error = 0;
	for (i = 0; i < n; i++) {
		unp = unp_list[i];
		if (unp->unp_gencnt <= gencnt) {
			struct xunpcb xu;
			xu.xu_len = sizeof xu;
			xu.xu_unpp = (struct  unpcb_compat *)unp;
			/*
			 * XXX - need more locking here to protect against
			 * connect/disconnect races for SMP.
			 */
			if (unp->unp_addr)
				bcopy(unp->unp_addr, &xu.xu_addr, 
				      unp->unp_addr->sun_len);
			if (unp->unp_conn && unp->unp_conn->unp_addr)
				bcopy(unp->unp_conn->unp_addr,
				      &xu.xu_caddr,
				      unp->unp_conn->unp_addr->sun_len);
			bcopy(unp, &xu.xu_unp, sizeof(xu.xu_unp));
			sotoxsocket(unp->unp_socket, &xu.xu_socket);
			error = SYSCTL_OUT(req, &xu, sizeof xu);
		}
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		xug.xug_gen = unp_gencnt;
		xug.xug_sogen = so_gencnt;
		xug.xug_count = unp_count;
		error = SYSCTL_OUT(req, &xug, sizeof xug);
	}
	FREE(unp_list, M_TEMP);
	lck_mtx_unlock(unp_mutex);
	return error;
}

SYSCTL_PROC(_net_local_dgram, OID_AUTO, pcblist, CTLFLAG_RD, 
	    (caddr_t)(long)SOCK_DGRAM, 0, unp_pcblist, "S,xunpcb",
	    "List of active local datagram sockets");
SYSCTL_PROC(_net_local_stream, OID_AUTO, pcblist, CTLFLAG_RD, 
	    (caddr_t)(long)SOCK_STREAM, 0, unp_pcblist, "S,xunpcb",
	    "List of active local stream sockets");

static void
unp_shutdown(struct unpcb *unp)
{
	struct socket *so;

	if (unp->unp_socket->so_type == SOCK_STREAM && unp->unp_conn &&
	    (so = unp->unp_conn->unp_socket))
		socantrcvmore(so);
}

static void
unp_drop(
	struct unpcb *unp,
	int errno)
{
	struct socket *so = unp->unp_socket;

	so->so_error = errno;
	unp_disconnect(unp);
}

#ifdef notdef
void
unp_drain()
{

}
#endif

int
unp_externalize(struct mbuf *rights)
{
	struct proc *p = current_proc();		/* XXX */
	int i;
	struct cmsghdr *cm = mtod(rights, struct cmsghdr *);
	struct fileglob **rp = (struct fileglob **)(cm + 1);
	struct fileproc *fp;
	struct fileglob *fg;
	int newfds = (cm->cmsg_len - sizeof(*cm)) / sizeof (int);
	int f;

	proc_fdlock(p);

	/*
	 * if the new FD's will not fit, then we free them all
	 */
	if (!fdavail(p, newfds)) {
		for (i = 0; i < newfds; i++) {
			fg = *rp;
			unp_discard_fdlocked(fg, p);
			*rp++ = 0;
		}
		proc_fdunlock(p);

		return (EMSGSIZE);
	}
	/*
	 * now change each pointer to an fd in the global table to 
	 * an integer that is the index to the local fd table entry
	 * that we set up to point to the global one we are transferring.
	 * XXX this assumes a pointer and int are the same size...!
	 */
	for (i = 0; i < newfds; i++) {
		if (fdalloc(p, 0, &f))
			panic("unp_externalize");
		fg = *rp;
		MALLOC_ZONE(fp, struct fileproc *, sizeof(struct fileproc), M_FILEPROC, M_WAITOK);
		bzero(fp, sizeof(struct fileproc));
		fp->f_iocount = 0;
		fp->f_fglob = fg;
		p->p_fd->fd_ofiles[f] = fp;
		fg_removeuipc(fg);
		*fdflags(p, f) &= ~UF_RESERVED;
		unp_rights--;
		*(int *)rp++ = f;
	}
	proc_fdunlock(p);

	return (0);
}

void
unp_init(void)
{
	unp_zone = zinit(sizeof(struct unpcb), 
			 (nmbclusters * sizeof(struct unpcb)), 
			  4096, "unpzone");
	if (unp_zone == 0)
		panic("unp_init");
	LIST_INIT(&unp_dhead);
	LIST_INIT(&unp_shead);
	
	unp_mutex = localdomain.dom_mtx;
}

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif

static int
unp_internalize(
	struct mbuf *control,
	struct proc *p)
{
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	struct fileglob **rp;
	struct fileproc *fp;
	register int i, error;
	int oldfds;
	int fdgetf_noref(proc_t, struct fileglob **, struct fileproc **);

	if (cm->cmsg_type != SCM_RIGHTS || cm->cmsg_level != SOL_SOCKET ||
	    cm->cmsg_len != control->m_len) {
	     return (EINVAL);
	}
	oldfds = (cm->cmsg_len - sizeof (*cm)) / sizeof (int);

	proc_fdlock(p);
	rp = (struct fileglob **)(cm + 1);

	for (i = 0; i < oldfds; i++) {
	     if (error = fdgetf_noref(p, *(int *)rp++, (struct fileglob **)0)) {
	             proc_fdunlock(p);
		     return (error);
	     }
	}
	rp = (struct fileglob **)(cm + 1);

	for (i = 0; i < oldfds; i++) {
		(void) fdgetf_noref(p, *(int *)rp, &fp);
		fg_insertuipc(fp->f_fglob);
		*rp++ = fp->f_fglob;
		unp_rights++;
	}
	proc_fdunlock(p);

	return (0);
}

static int	unp_defer, unp_gcing;

static void
unp_gc()
{
	register struct fileglob *fg, *nextfg;
	register struct socket *so;
	struct fileglob **extra_ref, **fpp;
	int nunref, i;

	lck_mtx_lock(uipc_lock);
	if (unp_gcing) {
		lck_mtx_unlock(uipc_lock);
		return;
	}
	unp_gcing = 1;
	unp_defer = 0;
	lck_mtx_unlock(uipc_lock);
	/* 
	 * before going through all this, set all FDs to 
	 * be NOT defered and NOT externally accessible
	 */
	for (fg = fmsghead.lh_first; fg != 0; fg = fg->f_msglist.le_next) {
		lck_mtx_lock(&fg->fg_lock);
		fg->fg_flag &= ~(FMARK|FDEFER);
		lck_mtx_unlock(&fg->fg_lock);
	}
	do {
		for (fg = fmsghead.lh_first; fg != 0; fg = fg->f_msglist.le_next) {
			lck_mtx_lock(&fg->fg_lock);
			/*
			 * If the file is not open, skip it
			 */
			if (fg->fg_count == 0) {
				lck_mtx_unlock(&fg->fg_lock);
				continue;
			}
			/*
			 * If we already marked it as 'defer'  in a
			 * previous pass, then try process it this time
			 * and un-mark it
			 */
			if (fg->fg_flag & FDEFER) {
				fg->fg_flag &= ~FDEFER;
				unp_defer--;
			} else {
				/*
				 * if it's not defered, then check if it's
				 * already marked.. if so skip it
				 */
				if (fg->fg_flag & FMARK){
					lck_mtx_unlock(&fg->fg_lock);
					continue;
				}
				/* 
				 * If all references are from messages
				 * in transit, then skip it. it's not 
				 * externally accessible.
				 */ 
				if (fg->fg_count == fg->fg_msgcount) {
					lck_mtx_unlock(&fg->fg_lock);
					continue;
				}
				/* 
				 * If it got this far then it must be
				 * externally accessible.
				 */
				fg->fg_flag |= FMARK;
			}
			/*
			 * either it was defered, or it is externally 
			 * accessible and not already marked so.
			 * Now check if it is possibly one of OUR sockets.
			 */ 
			if (fg->fg_type != DTYPE_SOCKET ||
			    (so = (struct socket *)fg->fg_data) == 0) {
				lck_mtx_unlock(&fg->fg_lock);
				continue;
			}
			if (so->so_proto->pr_domain != &localdomain ||
			    (so->so_proto->pr_flags&PR_RIGHTS) == 0) {
				lck_mtx_unlock(&fg->fg_lock);
				continue;
			}
#ifdef notdef
			/* if this code is enabled need to run under network funnel */
			if (so->so_rcv.sb_flags & SB_LOCK) {
				/*
				 * This is problematical; it's not clear
				 * we need to wait for the sockbuf to be
				 * unlocked (on a uniprocessor, at least),
				 * and it's also not clear what to do
				 * if sbwait returns an error due to receipt
				 * of a signal.  If sbwait does return
				 * an error, we'll go into an infinite
				 * loop.  Delete all of this for now.
				 */
				(void) sbwait(&so->so_rcv);
				goto restart;
			}
#endif
			/*
			 * So, Ok, it's one of our sockets and it IS externally
			 * accessible (or was defered). Now we look
			 * to see if we hold any file descriptors in its
			 * message buffers. Follow those links and mark them 
			 * as accessible too.
			 */
			unp_scan(so->so_rcv.sb_mb, unp_mark);
			lck_mtx_unlock(&fg->fg_lock);
		}
	} while (unp_defer);
	/*
	 * We grab an extra reference to each of the file table entries
	 * that are not otherwise accessible and then free the rights
	 * that are stored in messages on them.
	 *
	 * The bug in the orginal code is a little tricky, so I'll describe
	 * what's wrong with it here.
	 *
	 * It is incorrect to simply unp_discard each entry for f_msgcount
	 * times -- consider the case of sockets A and B that contain
	 * references to each other.  On a last close of some other socket,
	 * we trigger a gc since the number of outstanding rights (unp_rights)
	 * is non-zero.  If during the sweep phase the gc code un_discards,
	 * we end up doing a (full) closef on the descriptor.  A closef on A
	 * results in the following chain.  Closef calls soo_close, which
	 * calls soclose.   Soclose calls first (through the switch
	 * uipc_usrreq) unp_detach, which re-invokes unp_gc.  Unp_gc simply
	 * returns because the previous instance had set unp_gcing, and
	 * we return all the way back to soclose, which marks the socket
	 * with SS_NOFDREF, and then calls sofree.  Sofree calls sorflush
	 * to free up the rights that are queued in messages on the socket A,
	 * i.e., the reference on B.  The sorflush calls via the dom_dispose
	 * switch unp_dispose, which unp_scans with unp_discard.  This second
	 * instance of unp_discard just calls closef on B.
	 *
	 * Well, a similar chain occurs on B, resulting in a sorflush on B,
	 * which results in another closef on A.  Unfortunately, A is already
	 * being closed, and the descriptor has already been marked with
	 * SS_NOFDREF, and soclose panics at this point.
	 *
	 * Here, we first take an extra reference to each inaccessible
	 * descriptor.  Then, we call sorflush ourself, since we know
	 * it is a Unix domain socket anyhow.  After we destroy all the
	 * rights carried in messages, we do a last closef to get rid
	 * of our extra reference.  This is the last close, and the
	 * unp_detach etc will shut down the socket.
	 *
	 * 91/09/19, bsy@cs.cmu.edu
	 */
	extra_ref = _MALLOC(nfiles * sizeof(struct fileglob *), M_FILEGLOB, M_WAITOK);
	for (nunref = 0, fg = fmsghead.lh_first, fpp = extra_ref; fg != 0;
	    fg = nextfg) {
		lck_mtx_lock(&fg->fg_lock);

		nextfg = fg->f_msglist.le_next;
		/* 
		 * If it's not open, skip it
		 */
		if (fg->fg_count == 0) {
			lck_mtx_unlock(&fg->fg_lock);
			continue;
		}
		/* 
		 * If all refs are from msgs, and it's not marked accessible
		 * then it must be referenced from some unreachable cycle
		 * of (shut-down) FDs, so include it in our
		 * list of FDs to remove
		 */
		if (fg->fg_count == fg->fg_msgcount && !(fg->fg_flag & FMARK)) {
			fg->fg_count++;
			*fpp++ = fg;
			nunref++;
		}
		lck_mtx_unlock(&fg->fg_lock);
	}
	/* 
	 * for each FD on our hit list, do the following two things
	 */
	for (i = nunref, fpp = extra_ref; --i >= 0; ++fpp) {
		struct fileglob *tfg;

		tfg = *fpp;

		if (tfg->fg_type == DTYPE_SOCKET && tfg->fg_data != NULL) {
			sorflush((struct socket *)(tfg->fg_data));
		}
	}
	for (i = nunref, fpp = extra_ref; --i >= 0; ++fpp)
		closef_locked((struct fileproc *)0, *fpp, (struct proc *) NULL);
	unp_gcing = 0;
	FREE((caddr_t)extra_ref, M_FILEGLOB);

}

void
unp_dispose(struct mbuf *m)
{

	if (m) {
		unp_scan(m, unp_discard);
	}
}

static int
unp_listen(
	struct unpcb *unp,
	struct proc *p)
{

	cru2x(p->p_ucred, &unp->unp_peercred);
	unp->unp_flags |= UNP_HAVEPCCACHED;
	return (0);
}

/* should run under kernel funnel */ 
static void
unp_scan(
	struct mbuf *m0,
	void (*op)(struct fileglob *))
{
	struct mbuf *m;
	struct fileglob **rp;
	struct cmsghdr *cm;
	int i;
	int qfds;

	while (m0) {
		for (m = m0; m; m = m->m_next)
			if (m->m_type == MT_CONTROL &&
			    (size_t) m->m_len >= sizeof(*cm)) {
				cm = mtod(m, struct cmsghdr *);
				if (cm->cmsg_level != SOL_SOCKET ||
				    cm->cmsg_type != SCM_RIGHTS)
					continue;
				qfds = (cm->cmsg_len - sizeof *cm)
						/ sizeof (struct fileglob *);
				rp = (struct fileglob **)(cm + 1);
				for (i = 0; i < qfds; i++)
					(*op)(*rp++);
				break;		/* XXX, but saves time */
			}
		m0 = m0->m_act;
	}
}

/* should run under kernel funnel */
static void
unp_mark(struct fileglob *fg)
{
        lck_mtx_lock(&fg->fg_lock);

	if (fg->fg_flag & FMARK) {
	        lck_mtx_unlock(&fg->fg_lock);
		return;
	}
	fg->fg_flag |= (FMARK|FDEFER);

        lck_mtx_unlock(&fg->fg_lock);

	unp_defer++;
}

/* should run under kernel funnel */
static void
unp_discard(fg)
	struct fileglob *fg;
{
	struct proc *p = current_proc();		/* XXX */

	proc_fdlock(p);
	unp_discard_fdlocked(fg, p);
	proc_fdunlock(p);
}
static void
unp_discard_fdlocked(fg, p)
	struct fileglob *fg;
	struct proc *p;
{

	fg_removeuipc(fg);

	unp_rights--;
	(void) closef_locked((struct fileproc *)0, fg, p);
}
