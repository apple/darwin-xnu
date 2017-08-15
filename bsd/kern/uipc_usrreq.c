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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>		/* XXX must be before <sys/file.h> */
#include <sys/file_internal.h>
#include <sys/guarded.h>
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
#include <sys/mcache.h>

#include <kern/zalloc.h>
#include <kern/locks.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif /* CONFIG_MACF */

#include <mach/vm_param.h>

/*
 * Maximum number of FDs that can be passed in an mbuf
 */
#define UIPC_MAX_CMSG_FD	512

#define	f_msgcount f_fglob->fg_msgcount
#define	f_cred f_fglob->fg_cred
#define	f_ops f_fglob->fg_ops
#define	f_offset f_fglob->fg_offset
#define	f_data f_fglob->fg_data
struct	zone *unp_zone;
static	unp_gen_t unp_gencnt;
static	u_int unp_count;

static	lck_attr_t		*unp_mtx_attr;
static	lck_grp_t		*unp_mtx_grp;
static	lck_grp_attr_t		*unp_mtx_grp_attr;
static	lck_rw_t		*unp_list_mtx;

static  lck_mtx_t		*unp_disconnect_lock;
static	lck_mtx_t		*unp_connect_lock;
static  u_int                   disconnect_in_progress;

extern lck_mtx_t *uipc_lock;
static	struct unp_head unp_shead, unp_dhead;

/*
 * mDNSResponder tracing.  When enabled, endpoints connected to
 * /var/run/mDNSResponder will be traced; during each send on
 * the traced socket, we log the PID and process name of the
 * sending process.  We also print out a bit of info related
 * to the data itself; this assumes ipc_msg_hdr in dnssd_ipc.h
 * of mDNSResponder stays the same.
 */
#define	MDNSRESPONDER_PATH	"/var/run/mDNSResponder"

static int unpst_tracemdns;	/* enable tracing */

#define	MDNS_IPC_MSG_HDR_VERSION_1	1

struct mdns_ipc_msg_hdr {
	uint32_t version;
	uint32_t datalen;
	uint32_t ipc_flags;
	uint32_t op;
	union {
		void *context;
		uint32_t u32[2];
	} __attribute__((packed));
	uint32_t reg_index;
} __attribute__((packed));

/*
 * Unix communications domain.
 *
 * TODO:
 *	SEQPACKET, RDM
 *	rethink name space problems
 *	need a proper out-of-band
 *	lock pushdown
 */
static struct	sockaddr sun_noname = { sizeof (sun_noname), AF_LOCAL, { 0 } };
static ino_t	unp_ino;		/* prototype for fake inode numbers */

static int	unp_attach(struct socket *);
static void	unp_detach(struct unpcb *);
static int	unp_bind(struct unpcb *, struct sockaddr *, proc_t);
static int	unp_connect(struct socket *, struct sockaddr *, proc_t);
static void	unp_disconnect(struct unpcb *);
static void	unp_shutdown(struct unpcb *);
static void	unp_drop(struct unpcb *, int);
__private_extern__ void	unp_gc(void);
static void	unp_scan(struct mbuf *, void (*)(struct fileglob *, void *arg), void *arg);
static void	unp_mark(struct fileglob *, __unused void *);
static void	unp_discard(struct fileglob *, void *);
static int	unp_internalize(struct mbuf *, proc_t);
static int	unp_listen(struct unpcb *, proc_t);
static void	unpcb_to_compat(struct unpcb *, struct unpcb_compat *);
static void     unp_get_locks_in_order(struct socket *so, struct socket *conn_so);

static void 
unp_get_locks_in_order(struct socket *so, struct socket *conn_so) 
{
	if (so < conn_so) {
		socket_lock(conn_so, 1);
	} else {
		struct unpcb *unp = sotounpcb(so);
		unp->unp_flags |= UNP_DONTDISCONNECT;
		unp->rw_thrcount++;
		socket_unlock(so, 0);

		/* Get the locks in the correct order */
		socket_lock(conn_so, 1);
		socket_lock(so, 0);
		unp->rw_thrcount--;
		if (unp->rw_thrcount == 0) {
			unp->unp_flags &= ~UNP_DONTDISCONNECT;
			wakeup(unp);
		}
	}
}

static int
uipc_abort(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);
	unp_drop(unp, ECONNABORTED);
	unp_detach(unp);
	sofree(so);
	return (0);
}

static int
uipc_accept(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);

	/*
	 * Pass back name of connected socket,
	 * if it was bound and we are still connected
	 * (our peer may have closed already!).
	 */
	if (unp->unp_conn && unp->unp_conn->unp_addr) {
		*nam = dup_sockaddr((struct sockaddr *)
		    unp->unp_conn->unp_addr, 1);
	} else {
		*nam = dup_sockaddr((struct sockaddr *)&sun_noname, 1);
	}
	return (0);
}

/*
 * Returns:	0			Success
 *		EISCONN
 *	unp_attach:
 */
static int
uipc_attach(struct socket *so, __unused int proto, __unused proc_t p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp != 0)
		return (EISCONN);
	return (unp_attach(so));
}

static int
uipc_bind(struct socket *so, struct sockaddr *nam, proc_t p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);

	return (unp_bind(unp, nam, p));
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	unp_connect:???			[See elsewhere in this file]
 */
static int
uipc_connect(struct socket *so, struct sockaddr *nam, proc_t p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);
	return (unp_connect(so, nam, p));
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	unp_connect2:EPROTOTYPE		Protocol wrong type for socket
 *	unp_connect2:EINVAL		Invalid argument
 */
static int
uipc_connect2(struct socket *so1, struct socket *so2)
{
	struct unpcb *unp = sotounpcb(so1);

	if (unp == 0)
		return (EINVAL);

	return (unp_connect2(so1, so2));
}

/* control is EOPNOTSUPP */

static int
uipc_detach(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);

	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	unp_detach(unp);
	return (0);
}

static int
uipc_disconnect(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);
	unp_disconnect(unp);
	return (0);
}

/*
 * Returns:	0			Success
 *		EINVAL
 */
static int
uipc_listen(struct socket *so, __unused proc_t p)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0 || unp->unp_vnode == 0)
		return (EINVAL);
	return (unp_listen(unp, p));
}

static int
uipc_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == NULL)
		return (EINVAL);
	if (unp->unp_conn != NULL && unp->unp_conn->unp_addr != NULL) {
		*nam = dup_sockaddr((struct sockaddr *)
		    unp->unp_conn->unp_addr, 1);
	} else {
		*nam = dup_sockaddr((struct sockaddr *)&sun_noname, 1);
	}
	return (0);
}

static int
uipc_rcvd(struct socket *so, __unused int flags)
{
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;

	if (unp == 0)
		return (EINVAL);
	switch (so->so_type) {
	case SOCK_DGRAM:
		panic("uipc_rcvd DGRAM?");
		/*NOTREACHED*/

	case SOCK_STREAM:
#define	rcv (&so->so_rcv)
#define	snd (&so2->so_snd)
		if (unp->unp_conn == 0)
			break;
		
		so2 = unp->unp_conn->unp_socket;
		unp_get_locks_in_order(so, so2);
		/*
		 * Adjust backpressure on sender
		 * and wakeup any waiting to write.
		 */
		snd->sb_mbmax += unp->unp_mbcnt - rcv->sb_mbcnt;
		unp->unp_mbcnt = rcv->sb_mbcnt;
		snd->sb_hiwat += unp->unp_cc - rcv->sb_cc;
		unp->unp_cc = rcv->sb_cc;
		sowwakeup(so2);

		socket_unlock(so2, 1);

#undef snd
#undef rcv
		break;

	default:
		panic("uipc_rcvd unknown socktype");
	}
	return (0);
}

/* pru_rcvoob is EOPNOTSUPP */

/*
 * Returns:	0			Success
 *		EINVAL
 *		EOPNOTSUPP
 *		EPIPE
 *		ENOTCONN
 *		EISCONN
 *	unp_internalize:EINVAL
 *	unp_internalize:EBADF
 *	unp_connect:EAFNOSUPPORT	Address family not supported
 *	unp_connect:EINVAL		Invalid argument
 *	unp_connect:ENOTSOCK		Not a socket
 *	unp_connect:ECONNREFUSED	Connection refused
 *	unp_connect:EISCONN		Socket is connected
 *	unp_connect:EPROTOTYPE		Protocol wrong type for socket
 *	unp_connect:???
 *	sbappendaddr:ENOBUFS		[5th argument, contents modified]
 *	sbappendaddr:???		[whatever a filter author chooses]
 */
static int
uipc_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
    struct mbuf *control, proc_t p)
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

	if (control) {
		/* release lock to avoid deadlock (4436174) */
		socket_unlock(so, 0);
		error = unp_internalize(control, p);
		socket_lock(so, 0);
		if (error)
			goto release;
	}

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
		if (so != so2)
			unp_get_locks_in_order(so, so2);

		if (unp->unp_addr)
			from = (struct sockaddr *)unp->unp_addr;
		else
			from = &sun_noname;
		/*
		 * sbappendaddr() will fail when the receiver runs out of
		 * space; in contrast to SOCK_STREAM, we will lose messages
		 * for the SOCK_DGRAM case when the receiver's queue overflows.
		 * SB_UNIX on the socket buffer implies that the callee will
		 * not free the control message, if any, because we would need
		 * to call unp_dispose() on it.
		 */
		if (sbappendaddr(&so2->so_rcv, from, m, control, &error)) {
			control = NULL;
			sorwakeup(so2);
		} else if (control != NULL && error == 0) {
			/* A socket filter took control; don't touch it */
			control = NULL;
		}

		if (so != so2) 
			socket_unlock(so2, 1);

		m = NULL;
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
		unp_get_locks_in_order(so, so2);

		/* Check socket state again as we might have unlocked the socket 
		 * while trying to get the locks in order
		 */

		if ((so->so_state & SS_CANTSENDMORE)) {
			error = EPIPE;
			socket_unlock(so2, 1);
			break;
		}	

		if (unp->unp_flags & UNP_TRACE_MDNS) {
			struct mdns_ipc_msg_hdr hdr;

			if (mbuf_copydata(m, 0, sizeof (hdr), &hdr) == 0 &&
			    hdr.version  == ntohl(MDNS_IPC_MSG_HDR_VERSION_1)) {
				printf("%s[mDNSResponder] pid=%d (%s): op=0x%x\n",
				    __func__, p->p_pid, p->p_comm, ntohl(hdr.op));
			}
		}

		/*
		 * Send to paired receive port, and then reduce send buffer
		 * hiwater marks to maintain backpressure.  Wake up readers.
		 * SB_UNIX flag will allow new record to be appended to the
		 * receiver's queue even when it is already full.  It is
		 * possible, however, that append might fail.  In that case,
		 * we will need to call unp_dispose() on the control message;
		 * the callee will not free it since SB_UNIX is set.
		 */
		didreceive = control ?
		    sbappendcontrol(rcv, m, control, &error) : sbappend(rcv, m);

		snd->sb_mbmax -= rcv->sb_mbcnt - unp->unp_conn->unp_mbcnt;
		unp->unp_conn->unp_mbcnt = rcv->sb_mbcnt;
		if ((int32_t)snd->sb_hiwat >= 
		    (int32_t)(rcv->sb_cc - unp->unp_conn->unp_cc)) {
			snd->sb_hiwat -= rcv->sb_cc - unp->unp_conn->unp_cc;
		} else {
			snd->sb_hiwat = 0;
		}
		unp->unp_conn->unp_cc = rcv->sb_cc;
		if (didreceive) {
			control = NULL;
			sorwakeup(so2);
		} else if (control != NULL && error == 0) {
			/* A socket filter took control; don't touch it */
			control = NULL;
		}

		socket_unlock(so2, 1);
		m = NULL;
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

	if (control && error != 0) {
		socket_unlock(so, 0);
		unp_dispose(control);
		socket_lock(so, 0);
	}

release:
	if (control)
		m_freem(control);
	if (m)
		m_freem(m);
	return (error);
}

static int
uipc_sense(struct socket *so, void *ub, int isstat64)
{
	struct unpcb *unp = sotounpcb(so);
	struct socket *so2;
	blksize_t blksize;

	if (unp == 0)
		return (EINVAL);

	blksize = so->so_snd.sb_hiwat;
	if (so->so_type == SOCK_STREAM && unp->unp_conn != 0) {
		so2 = unp->unp_conn->unp_socket;
		blksize += so2->so_rcv.sb_cc;
	}
	if (unp->unp_ino == 0)
		unp->unp_ino = unp_ino++;

	if (isstat64 != 0) {
		struct stat64  *sb64;

		sb64 = (struct stat64 *)ub;
		sb64->st_blksize = blksize;
		sb64->st_dev = NODEV;
		sb64->st_ino = (ino64_t)unp->unp_ino;
	} else {
		struct stat *sb;

		sb = (struct stat *)ub;
		sb->st_blksize = blksize;
		sb->st_dev = NODEV;
		sb->st_ino = (ino_t)(uintptr_t)unp->unp_ino;
	}

	return (0);
}

/*
 * Returns:	0		Success
 *		EINVAL
 *
 * Notes:	This is not strictly correct, as unp_shutdown() also calls
 *		socantrcvmore().  These should maybe both be conditionalized
 *		on the 'how' argument in soshutdown() as called from the
 *		shutdown() system call.
 */
static int
uipc_shutdown(struct socket *so)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == 0)
		return (EINVAL);
	socantsendmore(so);
	unp_shutdown(unp);
	return (0);
}

/*
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 */
static int
uipc_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp = sotounpcb(so);

	if (unp == NULL)
		return (EINVAL);
	if (unp->unp_addr != NULL) {
		*nam = dup_sockaddr((struct sockaddr *)unp->unp_addr, 1);
	} else {
		*nam = dup_sockaddr((struct sockaddr *)&sun_noname, 1);
	}
	return (0);
}

struct pr_usrreqs uipc_usrreqs = {
	.pru_abort =		uipc_abort,
	.pru_accept =		uipc_accept,
	.pru_attach =		uipc_attach,
	.pru_bind =		uipc_bind,
	.pru_connect =		uipc_connect,
	.pru_connect2 =		uipc_connect2,
	.pru_detach =		uipc_detach,
	.pru_disconnect =	uipc_disconnect,
	.pru_listen =		uipc_listen,
	.pru_peeraddr =		uipc_peeraddr,
	.pru_rcvd =		uipc_rcvd,
	.pru_send =		uipc_send,
	.pru_sense =		uipc_sense,
	.pru_shutdown =		uipc_shutdown,
	.pru_sockaddr =		uipc_sockaddr,
	.pru_sosend =		sosend,
	.pru_soreceive =	soreceive,
};

int
uipc_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct unpcb *unp = sotounpcb(so);
	int error = 0;
	pid_t peerpid;
	struct socket *peerso;

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case LOCAL_PEERCRED:
			if (unp->unp_flags & UNP_HAVEPC) {
				error = sooptcopyout(sopt, &unp->unp_peercred,
				    sizeof (unp->unp_peercred));
			} else {
				if (so->so_type == SOCK_STREAM)
					error = ENOTCONN;
				else
					error = EINVAL;
			}
			break;
		case LOCAL_PEERPID:
		case LOCAL_PEEREPID:
			if (unp->unp_conn == NULL) {
				error = ENOTCONN;
				break;
			}
			peerso = unp->unp_conn->unp_socket;
			if (peerso == NULL)
				panic("peer is connected but has no socket?");
			unp_get_locks_in_order(so, peerso);
			if (sopt->sopt_name == LOCAL_PEEREPID &&
			    peerso->so_flags & SOF_DELEGATED)
				peerpid = peerso->e_pid;
			else
				peerpid = peerso->last_pid;
			socket_unlock(peerso, 1);
			error = sooptcopyout(sopt, &peerpid, sizeof (peerpid));
			break;
		case LOCAL_PEERUUID:
		case LOCAL_PEEREUUID:
			if (unp->unp_conn == NULL) {
				error = ENOTCONN;
				break;
			}
			peerso = unp->unp_conn->unp_socket;
			if (peerso == NULL)
				panic("peer is connected but has no socket?");
			unp_get_locks_in_order(so, peerso);
			if (sopt->sopt_name == LOCAL_PEEREUUID &&
			    peerso->so_flags & SOF_DELEGATED)
				error = sooptcopyout(sopt, &peerso->e_uuid,
				    sizeof (peerso->e_uuid));
			else
				error = sooptcopyout(sopt, &peerso->last_uuid,
				    sizeof (peerso->last_uuid));
			socket_unlock(peerso, 1);
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
static u_int32_t	unpst_sendspace = PIPSIZ;
static u_int32_t	unpst_recvspace = PIPSIZ;
static u_int32_t	unpdg_sendspace = 2*1024;	/* really max datagram size */
static u_int32_t	unpdg_recvspace = 4*1024;

static int	unp_rights;			/* file descriptors in flight */
static int	unp_disposed;			/* discarded file descriptors */

SYSCTL_DECL(_net_local_stream);
SYSCTL_INT(_net_local_stream, OID_AUTO, sendspace, CTLFLAG_RW | CTLFLAG_LOCKED,
   &unpst_sendspace, 0, "");
SYSCTL_INT(_net_local_stream, OID_AUTO, recvspace, CTLFLAG_RW | CTLFLAG_LOCKED,
   &unpst_recvspace, 0, "");
SYSCTL_INT(_net_local_stream, OID_AUTO, tracemdns, CTLFLAG_RW | CTLFLAG_LOCKED,
   &unpst_tracemdns, 0, "");
SYSCTL_DECL(_net_local_dgram);
SYSCTL_INT(_net_local_dgram, OID_AUTO, maxdgram, CTLFLAG_RW | CTLFLAG_LOCKED,
   &unpdg_sendspace, 0, "");
SYSCTL_INT(_net_local_dgram, OID_AUTO, recvspace, CTLFLAG_RW | CTLFLAG_LOCKED,
   &unpdg_recvspace, 0, "");
SYSCTL_DECL(_net_local);
SYSCTL_INT(_net_local, OID_AUTO, inflight, CTLFLAG_RD | CTLFLAG_LOCKED, &unp_rights, 0, "");

/*
 * Returns:	0			Success
 *		ENOBUFS
 *	soreserve:ENOBUFS
 */
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
	unp = (struct unpcb *)zalloc(unp_zone);
	if (unp == NULL)
		return (ENOBUFS);
	bzero(unp, sizeof (*unp));

	lck_mtx_init(&unp->unp_mtx, 
		unp_mtx_grp, unp_mtx_attr);

	lck_rw_lock_exclusive(unp_list_mtx);
	LIST_INIT(&unp->unp_refs);
	unp->unp_socket = so;
	unp->unp_gencnt = ++unp_gencnt;
	unp_count++;
	LIST_INSERT_HEAD(so->so_type == SOCK_DGRAM ?
	    &unp_dhead : &unp_shead, unp, unp_link);
	lck_rw_done(unp_list_mtx);
	so->so_pcb = (caddr_t)unp;
	/*
	 * Mark AF_UNIX socket buffers accordingly so that:
	 *
	 * a. In the SOCK_STREAM case, socket buffer append won't fail due to
	 *    the lack of space; this essentially loosens the sbspace() check,
	 *    since there is disconnect between sosend() and uipc_send() with
	 *    respect to flow control that might result in our dropping the
	 *    data in uipc_send().  By setting this, we allow for slightly
	 *    more records to be appended to the receiving socket to avoid
	 *    losing data (which we can't afford in the SOCK_STREAM case).
	 *    Flow control still takes place since we adjust the sender's
	 *    hiwat during each send.  This doesn't affect the SOCK_DGRAM
	 *    case and append would still fail when the queue overflows.
	 *
	 * b. In the presence of control messages containing internalized
	 *    file descriptors, the append routines will not free them since
	 *    we'd need to undo the work first via unp_dispose().
	 */
	so->so_rcv.sb_flags |= SB_UNIX;
	so->so_snd.sb_flags |= SB_UNIX;
	return (0);
}

static void
unp_detach(struct unpcb *unp)
{
	int so_locked = 1;

	lck_rw_lock_exclusive(unp_list_mtx);
	LIST_REMOVE(unp, unp_link);
	--unp_count; 
	++unp_gencnt;
	lck_rw_done(unp_list_mtx);
	if (unp->unp_vnode) {
		struct vnode *tvp = NULL;
		socket_unlock(unp->unp_socket, 0);

		/* Holding unp_connect_lock will avoid a race between
		 * a thread closing the listening socket and a thread
		 * connecting to it.
		 */
		lck_mtx_lock(unp_connect_lock);
		socket_lock(unp->unp_socket, 0);
		if (unp->unp_vnode) {
			tvp = unp->unp_vnode;
			unp->unp_vnode->v_socket = NULL;
			unp->unp_vnode = NULL;
		}
		lck_mtx_unlock(unp_connect_lock);
		if (tvp != NULL)
			vnode_rele(tvp);		/* drop the usecount */
	}
	if (unp->unp_conn)
		unp_disconnect(unp);
	while (unp->unp_refs.lh_first) {
		struct unpcb *unp2 = NULL;

		/* This datagram socket is connected to one or more
		 * sockets. In order to avoid a race condition between removing
		 * this reference and closing the connected socket, we need 
		 * to check disconnect_in_progress
		 */
		if (so_locked == 1) {
			socket_unlock(unp->unp_socket, 0);
			so_locked = 0;
		}
		lck_mtx_lock(unp_disconnect_lock);
		while (disconnect_in_progress != 0) {
			(void)msleep((caddr_t)&disconnect_in_progress, unp_disconnect_lock,
				PSOCK, "disconnect", NULL);
		}
		disconnect_in_progress = 1;
		lck_mtx_unlock(unp_disconnect_lock);

		/* Now we are sure that any unpcb socket disconnect is not happening */
		if (unp->unp_refs.lh_first != NULL) {
 			unp2 = unp->unp_refs.lh_first;
 			socket_lock(unp2->unp_socket, 1);
		}
		
		lck_mtx_lock(unp_disconnect_lock);
		disconnect_in_progress = 0;
		wakeup(&disconnect_in_progress);
		lck_mtx_unlock(unp_disconnect_lock);
			
		if (unp2 != NULL) {
			/* We already locked this socket and have a reference on it */
 			unp_drop(unp2, ECONNRESET);
 			socket_unlock(unp2->unp_socket, 1);
		}
	}

	if (so_locked == 0) {
		socket_lock(unp->unp_socket, 0);
		so_locked = 1;
	}
	soisdisconnected(unp->unp_socket);
	/* makes sure we're getting dealloced */
	unp->unp_socket->so_flags |= SOF_PCBCLEARING;
}

/*
 * Returns:	0			Success
 *		EAFNOSUPPORT
 *		EINVAL
 *		EADDRINUSE
 *		namei:???		[anything namei can return]
 *		vnode_authorize:???	[anything vnode_authorize can return]
 *
 * Notes:	p at this point is the current process, as this function is
 *		only called by sobind().
 */
static int
unp_bind(
	struct unpcb *unp,
	struct sockaddr *nam,
	proc_t p)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vnode *vp, *dvp;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error, namelen;
	struct nameidata nd;
	struct socket *so = unp->unp_socket;
	char buf[SOCK_MAXADDRLEN];

	if (nam->sa_family != 0 && nam->sa_family != AF_UNIX) {
		return (EAFNOSUPPORT);
	}

	if (unp->unp_vnode != NULL)
		return (EINVAL);
	namelen = soun->sun_len - offsetof(struct sockaddr_un, sun_path);
	if (namelen <= 0)
		return (EINVAL);
	/*
	 * Note: sun_path is not a zero terminated "C" string
	 */
	ASSERT(namelen < SOCK_MAXADDRLEN);
	bcopy(soun->sun_path, buf, namelen);
	buf[namelen] = 0;
	
	socket_unlock(so, 0);

	NDINIT(&nd, CREATE, OP_MKFIFO, FOLLOW | LOCKPARENT, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(buf), ctx);
	/* SHOULD BE ABLE TO ADOPT EXISTING AND wakeup() ALA FIFO's */
	error = namei(&nd);
	if (error) {
		socket_lock(so, 0);
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

		socket_lock(so, 0);
		return (EADDRINUSE);
	}

	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VSOCK);
	VATTR_SET(&va, va_mode, (ACCESSPERMS & ~p->p_fd->fd_cmask));

#if CONFIG_MACF
	error = mac_vnode_check_create(ctx,
	    nd.ni_dvp, &nd.ni_cnd, &va);

	if (error == 0)
#endif /* CONFIG_MACF */
#if CONFIG_MACF_SOCKET_SUBSET
	error = mac_vnode_check_uipc_bind(ctx,
	    nd.ni_dvp, &nd.ni_cnd, &va);

	if (error == 0)
#endif /* MAC_SOCKET_SUBSET */
	/* authorize before creating */
	error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx);

	if (!error) {
		/* create the socket */
		error = vn_create(dvp, &vp, &nd, &va, 0, 0, NULL, ctx);
	}

	nameidone(&nd);
	vnode_put(dvp);

	if (error) {
		socket_lock(so, 0);
		return (error);
	}
	vnode_ref(vp);	/* gain a longterm reference */
	socket_lock(so, 0);
	vp->v_socket = unp->unp_socket;
	unp->unp_vnode = vp;
	unp->unp_addr = (struct sockaddr_un *)dup_sockaddr(nam, 1);
	vnode_put(vp);		/* drop the iocount */

	return (0);
}


/*
 * Returns:	0			Success
 *		EAFNOSUPPORT		Address family not supported
 *		EINVAL			Invalid argument
 *		ENOTSOCK		Not a socket
 *		ECONNREFUSED		Connection refused
 *		EPROTOTYPE		Protocol wrong type for socket
 *		EISCONN			Socket is connected
 *	unp_connect2:EPROTOTYPE		Protocol wrong type for socket
 *	unp_connect2:EINVAL		Invalid argument
 *	namei:???			[anything namei can return]
 *	vnode_authorize:????		[anything vnode_authorize can return]
 *
 * Notes:	p at this point is the current process, as this function is
 *		only called by sosend(), sendfile(), and soconnectlock().
 */
static int
unp_connect(struct socket *so, struct sockaddr *nam, __unused proc_t p)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vnode *vp;
	struct socket *so2, *so3, *list_so=NULL;
	struct unpcb *unp, *unp2, *unp3;
	vfs_context_t ctx = vfs_context_current();
	int error, len;
	struct nameidata nd;
	char buf[SOCK_MAXADDRLEN];

	if (nam->sa_family != 0 && nam->sa_family != AF_UNIX) {
		return (EAFNOSUPPORT);
	}

	unp = sotounpcb(so);
	so2 = so3 = NULL;

	len = nam->sa_len - offsetof(struct sockaddr_un, sun_path);
	if (len <= 0)
		return (EINVAL);
	/*
	 * Note: sun_path is not a zero terminated "C" string
	 */
	ASSERT(len < SOCK_MAXADDRLEN);
	bcopy(soun->sun_path, buf, len);
	buf[len] = 0;

	socket_unlock(so, 0);

	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(buf), ctx);
	error = namei(&nd);
	if (error) {
		socket_lock(so, 0);
		return (error);
	}
	nameidone(&nd);
	vp = nd.ni_vp;
	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		socket_lock(so, 0);
		goto out;
	}

#if CONFIG_MACF_SOCKET_SUBSET
	error = mac_vnode_check_uipc_connect(ctx, vp, so);
	if (error) {
		socket_lock(so, 0);
		goto out;
	}
#endif /* MAC_SOCKET_SUBSET */

	error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, ctx);
	if (error) {
		socket_lock(so, 0);
		goto out;
	}

	lck_mtx_lock(unp_connect_lock);

	if (vp->v_socket == 0) {
		lck_mtx_unlock(unp_connect_lock);
		error = ECONNREFUSED;
		socket_lock(so, 0);
		goto out;
	}

	socket_lock(vp->v_socket, 1); /* Get a reference on the listening socket */
	so2 = vp->v_socket;
	lck_mtx_unlock(unp_connect_lock);


	if (so2->so_pcb == NULL) {
		error = ECONNREFUSED;
		if (so != so2) {
			socket_unlock(so2, 1);
			socket_lock(so, 0);
		} else {
			/* Release the reference held for the listen socket */
			VERIFY(so2->so_usecount > 0);
			so2->so_usecount--;
		}
		goto out;
	}

	if (so < so2) {
		socket_unlock(so2, 0);
		socket_lock(so, 0);
		socket_lock(so2, 0);
	} else if (so > so2) {
		socket_lock(so, 0);
	}
	/*
	 * Check if socket was connected while we were trying to
	 * get the socket locks in order.
	 * XXX - probably shouldn't return an error for SOCK_DGRAM
	 */
	if ((so->so_state & SS_ISCONNECTED) != 0) {
		error = EISCONN;
		goto decref_out;
	}

	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		goto decref_out;
	}

	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		/* Release the incoming socket but keep a reference */
		socket_unlock(so, 0);

		if ((so2->so_options & SO_ACCEPTCONN) == 0 ||
		    (so3 = sonewconn(so2, 0, nam)) == 0) {
			error = ECONNREFUSED;
			if (so != so2) {
				socket_unlock(so2, 1);
				socket_lock(so, 0);
			} else {
				socket_lock(so, 0);
				/* Release the reference held for
				 * listen socket.
				 */
				VERIFY(so2->so_usecount > 0);
				so2->so_usecount--;
			}
			goto out;
		}
		unp2 = sotounpcb(so2);
		unp3 = sotounpcb(so3);
		if (unp2->unp_addr)
			unp3->unp_addr = (struct sockaddr_un *)
			    dup_sockaddr((struct sockaddr *)unp2->unp_addr, 1);

		/*
		 * unp_peercred management:
		 *
		 * The connecter's (client's) credentials are copied
		 * from its process structure at the time of connect()
		 * (which is now).
		 */
		cru2x(vfs_context_ucred(ctx), &unp3->unp_peercred);
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

		/* Here we need to have both so and so2 locks and so2
		 * is already locked. Lock ordering is required.
		 */
		if (so < so2) {
			socket_unlock(so2, 0);
			socket_lock(so, 0);
			socket_lock(so2, 0);
		} else {
			socket_lock(so, 0);
		}

		/* Check again if the socket state changed when its lock was released */
		if ((so->so_state & SS_ISCONNECTED) != 0) {
			error = EISCONN;
			socket_unlock(so2, 1);
			socket_lock(so3, 0);
			sofreelastref(so3, 1);
                	goto out;
		}
		memcpy(&unp->unp_peercred, &unp2->unp_peercred,
		    sizeof (unp->unp_peercred));
		unp->unp_flags |= UNP_HAVEPC;

#if CONFIG_MACF_SOCKET
		/* XXXMAC: recursive lock: SOCK_LOCK(so); */
		mac_socketpeer_label_associate_socket(so, so3);
		mac_socketpeer_label_associate_socket(so3, so);
		/* XXXMAC: SOCK_UNLOCK(so); */
#endif /* MAC_SOCKET */

		/* Hold the reference on listening socket until the end */
		socket_unlock(so2, 0);
		list_so = so2;

		/* Lock ordering doesn't matter because so3 was just created */
		socket_lock(so3, 1);
		so2 = so3;

		/*
		 * Enable tracing for mDNSResponder endpoints.  (The use
		 * of sizeof instead of strlen below takes the null
		 * terminating character into account.)
		 */
		if (unpst_tracemdns &&
		    !strncmp(soun->sun_path, MDNSRESPONDER_PATH,
		    sizeof (MDNSRESPONDER_PATH))) {
			unp->unp_flags |= UNP_TRACE_MDNS;
			unp2->unp_flags |= UNP_TRACE_MDNS;
		}
	}
	
	error = unp_connect2(so, so2);

decref_out:
	if (so2 != NULL) {
		if (so != so2) {
			socket_unlock(so2, 1);
		} else {
			/* Release the extra reference held for the listen socket.
			 * This is possible only for SOCK_DGRAM sockets. We refuse
			 * connecting to the same socket for SOCK_STREAM sockets.
			 */
			VERIFY(so2->so_usecount > 0);
			so2->so_usecount--;
		}
	}

	if (list_so != NULL) {
		socket_lock(list_so, 0);
		socket_unlock(list_so, 1);
	}

out:
	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	vnode_put(vp);
	return (error);
}

/*
 * Returns:	0			Success
 *		EPROTOTYPE		Protocol wrong type for socket
 *		EINVAL			Invalid argument
 */
int
unp_connect2(struct socket *so, struct socket *so2)
{
	struct unpcb *unp = sotounpcb(so);
	struct unpcb *unp2;

	if (so2->so_type != so->so_type)
		return (EPROTOTYPE);

	unp2 = sotounpcb(so2);

	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&unp2->unp_mtx, LCK_MTX_ASSERT_OWNED);

	/* Verify both sockets are still opened */
	if (unp == 0 || unp2 == 0)
		return (EINVAL);

	unp->unp_conn = unp2;
	so2->so_usecount++; 
	
	switch (so->so_type) {

	case SOCK_DGRAM:
		LIST_INSERT_HEAD(&unp2->unp_refs, unp, unp_reflink);

		if (so != so2) {	
			/* Avoid lock order reversals due to drop/acquire in soisconnected. */
 			/* Keep an extra reference on so2 that will be dropped
			 * soon after getting the locks in order 
			 */ 
			socket_unlock(so2, 0);
			soisconnected(so);
			unp_get_locks_in_order(so, so2);
			VERIFY(so2->so_usecount > 0);
			so2->so_usecount--;
		} else {
			soisconnected(so);
		}

		break;

	case SOCK_STREAM:
		/* This takes care of socketpair */
		if (!(unp->unp_flags & UNP_HAVEPC) &&
		    !(unp2->unp_flags & UNP_HAVEPC)) {
			cru2x(kauth_cred_get(), &unp->unp_peercred);
			unp->unp_flags |= UNP_HAVEPC;

			cru2x(kauth_cred_get(), &unp2->unp_peercred);
			unp2->unp_flags |= UNP_HAVEPC;
		}
		unp2->unp_conn = unp;
		so->so_usecount++;

		/* Avoid lock order reversals due to drop/acquire in soisconnected. */
		socket_unlock(so, 0);
		soisconnected(so2);

		/* Keep an extra reference on so2, that will be dropped soon after
		 * getting the locks in order again.
		 */
		socket_unlock(so2, 0);

		socket_lock(so, 0);
		soisconnected(so);

		unp_get_locks_in_order(so, so2);
		/* Decrement the extra reference left before */
		VERIFY(so2->so_usecount > 0);
		so2->so_usecount--;
		break;

	default:
		panic("unknown socket type %d in unp_connect2", so->so_type);
	}
	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&unp2->unp_mtx, LCK_MTX_ASSERT_OWNED);
	return (0);
}

static void
unp_disconnect(struct unpcb *unp)
{
	struct unpcb *unp2 = NULL;
	struct socket *so2 = NULL, *so;
	struct socket *waitso;
	int so_locked = 1, strdisconn = 0;

	so = unp->unp_socket;
	if (unp->unp_conn == NULL) {
		return;
	}
	lck_mtx_lock(unp_disconnect_lock);
	while (disconnect_in_progress != 0) {
		if (so_locked == 1) {
			socket_unlock(so, 0);
			so_locked = 0;
		}
		(void)msleep((caddr_t)&disconnect_in_progress, unp_disconnect_lock,
			PSOCK, "disconnect", NULL);
	}
	disconnect_in_progress = 1;
	lck_mtx_unlock(unp_disconnect_lock);

	if (so_locked == 0) {
		socket_lock(so, 0);
		so_locked = 1;
	}

	unp2 = unp->unp_conn;

	if (unp2 == 0 || unp2->unp_socket == NULL) {
		goto out;
	}
	so2 = unp2->unp_socket;

try_again:
	if (so == so2) {
		if (so_locked == 0) {
			socket_lock(so, 0);
		}
		waitso = so;
	} else if (so < so2) {
		if (so_locked == 0) {
			socket_lock(so, 0);
		}
		socket_lock(so2, 1);
		waitso = so2;
	} else {
		if (so_locked == 1) { 
			socket_unlock(so, 0);
		}
		socket_lock(so2, 1);
		socket_lock(so, 0);
		waitso = so;
	}
	so_locked = 1;

	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&unp2->unp_mtx, LCK_MTX_ASSERT_OWNED);

	/* Check for the UNP_DONTDISCONNECT flag, if it
	 * is set, release both sockets and go to sleep
	 */
	
	if ((((struct unpcb *)waitso->so_pcb)->unp_flags & UNP_DONTDISCONNECT) != 0) {
		if (so != so2) {
			socket_unlock(so2, 1);
		}
		so_locked = 0;

		(void)msleep(waitso->so_pcb, &unp->unp_mtx, 
			PSOCK | PDROP, "unpdisconnect", NULL);
		goto try_again;
	}
	
	if (unp->unp_conn == NULL) {
		panic("unp_conn became NULL after sleep");
	}

	unp->unp_conn = NULL;
	VERIFY(so2->so_usecount > 0);
	so2->so_usecount--;

	if (unp->unp_flags & UNP_TRACE_MDNS)
		unp->unp_flags &= ~UNP_TRACE_MDNS;

	switch (unp->unp_socket->so_type) {

	case SOCK_DGRAM:
		LIST_REMOVE(unp, unp_reflink);
		unp->unp_socket->so_state &= ~SS_ISCONNECTED;
		if (so != so2)
			socket_unlock(so2, 1);
		break;

	case SOCK_STREAM:
		unp2->unp_conn = NULL;
		VERIFY(so2->so_usecount > 0);
		so->so_usecount--;

		/* Set the socket state correctly but do a wakeup later when
		 * we release all locks except the socket lock, this will avoid
		 * a deadlock.
		 */
		unp->unp_socket->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
		unp->unp_socket->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE|SS_ISDISCONNECTED);

		unp2->unp_socket->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
		unp->unp_socket->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE|SS_ISDISCONNECTED);

		if (unp2->unp_flags & UNP_TRACE_MDNS)
			unp2->unp_flags &= ~UNP_TRACE_MDNS;

		strdisconn = 1;
		break;
	default:
		panic("unknown socket type %d", so->so_type);
	}
out:
	lck_mtx_lock(unp_disconnect_lock);
	disconnect_in_progress = 0;
	wakeup(&disconnect_in_progress);
	lck_mtx_unlock(unp_disconnect_lock);

	if (strdisconn) {
		socket_unlock(so, 0);
		soisdisconnected(so2);
		socket_unlock(so2, 1);

		socket_lock(so,0);
		soisdisconnected(so);
	}
	lck_mtx_assert(&unp->unp_mtx, LCK_MTX_ASSERT_OWNED);
	return;
}

/*
 * unpcb_to_compat copies specific bits of a unpcb to a unpcb_compat format.
 * The unpcb_compat data structure is passed to user space and must not change.
 */
static void
unpcb_to_compat(struct unpcb *up, struct unpcb_compat *cp)
{
#if defined(__LP64__)
	cp->unp_link.le_next = (u_int32_t)
	    VM_KERNEL_ADDRPERM(up->unp_link.le_next);
	cp->unp_link.le_prev = (u_int32_t)
	    VM_KERNEL_ADDRPERM(up->unp_link.le_prev);
#else
	cp->unp_link.le_next = (struct unpcb_compat *)
	    VM_KERNEL_ADDRPERM(up->unp_link.le_next);
	cp->unp_link.le_prev = (struct unpcb_compat **)
	    VM_KERNEL_ADDRPERM(up->unp_link.le_prev);
#endif
	cp->unp_socket = (_UNPCB_PTR(struct socket *))
	    VM_KERNEL_ADDRPERM(up->unp_socket);
	cp->unp_vnode = (_UNPCB_PTR(struct vnode *))
	    VM_KERNEL_ADDRPERM(up->unp_vnode);
	cp->unp_ino = up->unp_ino;
	cp->unp_conn = (_UNPCB_PTR(struct unpcb_compat *))
	    VM_KERNEL_ADDRPERM(up->unp_conn);
	cp->unp_refs = (u_int32_t)VM_KERNEL_ADDRPERM(up->unp_refs.lh_first);
#if defined(__LP64__)
	cp->unp_reflink.le_next =
	    (u_int32_t)VM_KERNEL_ADDRPERM(up->unp_reflink.le_next);
	cp->unp_reflink.le_prev =
	    (u_int32_t)VM_KERNEL_ADDRPERM(up->unp_reflink.le_prev);
#else
	cp->unp_reflink.le_next =
	    (struct unpcb_compat *)VM_KERNEL_ADDRPERM(up->unp_reflink.le_next);
	cp->unp_reflink.le_prev =
	    (struct unpcb_compat **)VM_KERNEL_ADDRPERM(up->unp_reflink.le_prev);
#endif
	cp->unp_addr = (_UNPCB_PTR(struct sockaddr_un *))
	    VM_KERNEL_ADDRPERM(up->unp_addr);
	cp->unp_cc = up->unp_cc;
	cp->unp_mbcnt = up->unp_mbcnt;
	cp->unp_gencnt = up->unp_gencnt;
}

static int
unp_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp,arg2)
	int error, i, n;
	struct unpcb *unp, **unp_list;
	unp_gen_t gencnt;
	struct xunpgen xug;
	struct unp_head *head;

	lck_rw_lock_shared(unp_list_mtx);
	head = ((intptr_t)arg1 == SOCK_DGRAM ? &unp_dhead : &unp_shead);

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		n = unp_count;
		req->oldidx = 2 * sizeof (xug) + (n + n / 8) *
		    sizeof (struct xunpcb);
		lck_rw_done(unp_list_mtx);
		return (0);
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(unp_list_mtx);
		return (EPERM);
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = unp_gencnt;
	n = unp_count;

	bzero(&xug, sizeof (xug));
	xug.xug_len = sizeof (xug);
	xug.xug_count = n;
	xug.xug_gen = gencnt;
	xug.xug_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xug, sizeof (xug));
	if (error) {
		lck_rw_done(unp_list_mtx);
		return (error);
	}

	/*
	 * We are done if there is no pcb
	 */
	if (n == 0)  {
		lck_rw_done(unp_list_mtx);
		return (0);
	}

	MALLOC(unp_list, struct unpcb **, n * sizeof (*unp_list),
	    M_TEMP, M_WAITOK);
	if (unp_list == 0) {
		lck_rw_done(unp_list_mtx);
		return (ENOMEM);
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

			bzero(&xu, sizeof (xu));
			xu.xu_len = sizeof (xu);
			xu.xu_unpp = (_UNPCB_PTR(struct unpcb_compat *))
			    VM_KERNEL_ADDRPERM(unp);
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
			unpcb_to_compat(unp, &xu.xu_unp);
			sotoxsocket(unp->unp_socket, &xu.xu_socket);
			error = SYSCTL_OUT(req, &xu, sizeof (xu));
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
		bzero(&xug, sizeof (xug));
		xug.xug_len = sizeof (xug);
		xug.xug_gen = unp_gencnt;
		xug.xug_sogen = so_gencnt;
		xug.xug_count = unp_count;
		error = SYSCTL_OUT(req, &xug, sizeof (xug));
	}
	FREE(unp_list, M_TEMP);
	lck_rw_done(unp_list_mtx);
	return (error);
}

SYSCTL_PROC(_net_local_dgram, OID_AUTO, pcblist,
            CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
            (caddr_t)(long)SOCK_DGRAM, 0, unp_pcblist, "S,xunpcb",
            "List of active local datagram sockets");
SYSCTL_PROC(_net_local_stream, OID_AUTO, pcblist,
            CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
            (caddr_t)(long)SOCK_STREAM, 0, unp_pcblist, "S,xunpcb",
            "List of active local stream sockets");


static int
unp_pcblist64 SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp,arg2)
	int error, i, n;
	struct unpcb *unp, **unp_list;
	unp_gen_t gencnt;
	struct xunpgen xug;
	struct unp_head *head;

	lck_rw_lock_shared(unp_list_mtx);
	head = ((intptr_t)arg1 == SOCK_DGRAM ? &unp_dhead : &unp_shead);

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		n = unp_count;
		req->oldidx = 2 * sizeof (xug) + (n + n / 8) *
		    (sizeof (struct xunpcb64)); 
		lck_rw_done(unp_list_mtx);
		return (0);
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(unp_list_mtx);
		return (EPERM);
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = unp_gencnt;
	n = unp_count;

	bzero(&xug, sizeof (xug));
	xug.xug_len = sizeof (xug);
	xug.xug_count = n;
	xug.xug_gen = gencnt;
	xug.xug_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xug, sizeof (xug));
	if (error) {
		lck_rw_done(unp_list_mtx);
		return (error);
	}

	/*
	 * We are done if there is no pcb
	 */
	if (n == 0)  {
		lck_rw_done(unp_list_mtx);
		return (0);
	}

	MALLOC(unp_list, struct unpcb **, n * sizeof (*unp_list),
	    M_TEMP, M_WAITOK);
	if (unp_list == 0) {
		lck_rw_done(unp_list_mtx);
		return (ENOMEM);
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
			struct xunpcb64 xu;
			size_t		xu_len = sizeof(struct xunpcb64);

			bzero(&xu, xu_len);
			xu.xu_len = xu_len;
			xu.xu_unpp = (u_int64_t)VM_KERNEL_ADDRPERM(unp);
			xu.xunp_link.le_next = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_link.le_next);
			xu.xunp_link.le_prev = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_link.le_prev);
			xu.xunp_socket = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_socket);
			xu.xunp_vnode = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_vnode);
			xu.xunp_ino = unp->unp_ino;
			xu.xunp_conn = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_conn);
			xu.xunp_refs = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_refs.lh_first);
			xu.xunp_reflink.le_next = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_reflink.le_next);
			xu.xunp_reflink.le_prev = (u_int64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_reflink.le_prev);
			xu.xunp_cc = unp->unp_cc;
			xu.xunp_mbcnt = unp->unp_mbcnt;
			xu.xunp_gencnt = unp->unp_gencnt;

			if (unp->unp_socket)
				sotoxsocket64(unp->unp_socket, &xu.xu_socket);

			/*
			 * XXX - need more locking here to protect against
			 * connect/disconnect races for SMP.
			 */
                        if (unp->unp_addr)
                                bcopy(unp->unp_addr, &xu.xunp_addr,
                                    unp->unp_addr->sun_len);
                        if (unp->unp_conn && unp->unp_conn->unp_addr)
                                bcopy(unp->unp_conn->unp_addr,
                                    &xu.xunp_caddr,
                                    unp->unp_conn->unp_addr->sun_len);

			error = SYSCTL_OUT(req, &xu, xu_len);
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
		bzero(&xug, sizeof (xug));
		xug.xug_len = sizeof (xug);
		xug.xug_gen = unp_gencnt;
		xug.xug_sogen = so_gencnt;
		xug.xug_count = unp_count;
		error = SYSCTL_OUT(req, &xug, sizeof (xug));
	}
	FREE(unp_list, M_TEMP);
	lck_rw_done(unp_list_mtx);
	return (error);
}

SYSCTL_PROC(_net_local_dgram, OID_AUTO, pcblist64,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
	    (caddr_t)(long)SOCK_DGRAM, 0, unp_pcblist64, "S,xunpcb64",
	    "List of active local datagram sockets 64 bit");
SYSCTL_PROC(_net_local_stream, OID_AUTO, pcblist64,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
	    (caddr_t)(long)SOCK_STREAM, 0, unp_pcblist64, "S,xunpcb64",
	    "List of active local stream sockets 64 bit");


static void
unp_shutdown(struct unpcb *unp)
{
	struct socket *so = unp->unp_socket;
	struct socket *so2;
	if (unp->unp_socket->so_type == SOCK_STREAM && unp->unp_conn) {
		so2 = unp->unp_conn->unp_socket;
		unp_get_locks_in_order(so, so2);
		socantrcvmore(so2);
		socket_unlock(so2, 1);
	}
}

static void
unp_drop(struct unpcb *unp, int errno)
{
	struct socket *so = unp->unp_socket;

	so->so_error = errno;
	unp_disconnect(unp);
}

/*
 * Returns:	0			Success
 *		EMSGSIZE		The new fd's will not fit
 *		ENOBUFS			Cannot alloc struct fileproc
 */
int
unp_externalize(struct mbuf *rights)
{
	proc_t p = current_proc();		/* XXX */
	int i;
	struct cmsghdr *cm = mtod(rights, struct cmsghdr *);
	struct fileglob **rp = (struct fileglob **)(cm + 1);
	int *fds = (int *)(cm + 1);
	struct fileproc *fp;
	struct fileproc **fileproc_l;
	int newfds = (cm->cmsg_len - sizeof (*cm)) / sizeof (int);
	int f, error = 0;

	MALLOC(fileproc_l, struct fileproc **,
	    newfds * sizeof (struct fileproc *), M_TEMP, M_WAITOK);
	if (fileproc_l == NULL) {
		error = ENOMEM;
		goto discard;
	}

	proc_fdlock(p);

	/*
	 * if the new FD's will not fit, then we free them all
	 */
	if (!fdavail(p, newfds)) {
		proc_fdunlock(p);
		error = EMSGSIZE;
		goto discard;
	}
	/*
	 * now change each pointer to an fd in the global table to
	 * an integer that is the index to the local fd table entry
	 * that we set up to point to the global one we are transferring.
	 * XXX (1) this assumes a pointer and int are the same size, 
	 * XXX     or the mbuf can hold the expansion
	 * XXX (2) allocation failures should be non-fatal
	 */
	for (i = 0; i < newfds; i++) {
#if CONFIG_MACF_SOCKET
		/*
		 * If receive access is denied, don't pass along
		 * and error message, just discard the descriptor.
		 */
		if (mac_file_check_receive(kauth_cred_get(), rp[i])) {
			proc_fdunlock(p);
			unp_discard(rp[i], p);
			fds[i] = 0;
			proc_fdlock(p);
			continue;
		}
#endif
		if (fdalloc(p, 0, &f))
			panic("unp_externalize:fdalloc");
		fp = fileproc_alloc_init(NULL);
		if (fp == NULL)
			panic("unp_externalize: MALLOC_ZONE");
		fp->f_iocount = 0;
		fp->f_fglob = rp[i];
		if (fg_removeuipc_mark(rp[i])) {

			/*
			 * Take an iocount on the fp for completing the
			 * removal from the global msg queue
			 */
			fp->f_iocount++;
			fileproc_l[i] = fp;
		} else {
			fileproc_l[i] = NULL;
		}
		procfdtbl_releasefd(p, f, fp);
		fds[i] = f;
	}
	proc_fdunlock(p);

	for (i = 0; i < newfds; i++) {
		if (fileproc_l[i] != NULL) {
			VERIFY(fileproc_l[i]->f_fglob != NULL &&
			    (fileproc_l[i]->f_fglob->fg_lflags & FG_RMMSGQ));
			VERIFY(fds[i] > 0);
			fg_removeuipc(fileproc_l[i]->f_fglob);

			/* Drop the iocount */
			fp_drop(p, fds[i], fileproc_l[i], 0);
			fileproc_l[i] = NULL;
		}
		if (fds[i] != 0)
			(void) OSAddAtomic(-1, &unp_rights);
	}

discard:
	if (fileproc_l != NULL)
		FREE(fileproc_l, M_TEMP);
	if (error) {
		for (i = 0; i < newfds; i++) {
			unp_discard(*rp, p);
			*rp++ = NULL;
		}
	}
	return (error);
}

void
unp_init(void)
{
	_CASSERT(UIPC_MAX_CMSG_FD >= (MCLBYTES / sizeof(int)));
	unp_zone = zinit(sizeof (struct unpcb),
	    (nmbclusters * sizeof (struct unpcb)), 4096, "unpzone");

	if (unp_zone == 0)
		panic("unp_init");
	LIST_INIT(&unp_dhead);
	LIST_INIT(&unp_shead);

	/*
	 * allocate lock group attribute and group for udp pcb mutexes
	 */
	unp_mtx_grp_attr = lck_grp_attr_alloc_init();

	unp_mtx_grp = lck_grp_alloc_init("unp_list", unp_mtx_grp_attr);

	unp_mtx_attr = lck_attr_alloc_init();

	if ((unp_list_mtx = lck_rw_alloc_init(unp_mtx_grp,
	    unp_mtx_attr)) == NULL)
		return;	/* pretty much dead if this fails... */

	if ((unp_disconnect_lock = lck_mtx_alloc_init(unp_mtx_grp,
		unp_mtx_attr)) == NULL)
		return;

	if ((unp_connect_lock = lck_mtx_alloc_init(unp_mtx_grp,
		unp_mtx_attr)) == NULL)
		return;
}

#ifndef MIN
#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/*
 * Returns:	0			Success
 *		EINVAL
 *	fdgetf_noref:EBADF
 */
static int
unp_internalize(struct mbuf *control, proc_t p)
{
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	int *fds;
	struct fileglob **rp;
	struct fileproc *fp;
	int i, error;
	int oldfds;
	uint8_t fg_ins[UIPC_MAX_CMSG_FD / 8];

	/* 64bit: cmsg_len is 'uint32_t', m_len is 'long' */
	if (cm->cmsg_type != SCM_RIGHTS || cm->cmsg_level != SOL_SOCKET ||
	    (socklen_t)cm->cmsg_len != (socklen_t)control->m_len) {
		return (EINVAL);
	}
	oldfds = (cm->cmsg_len - sizeof (*cm)) / sizeof (int);
	bzero(fg_ins, sizeof(fg_ins));

	proc_fdlock(p);
	fds = (int *)(cm + 1);

	for (i = 0; i < oldfds; i++) {
		struct fileproc *tmpfp;
		if (((error = fdgetf_noref(p, fds[i], &tmpfp)) != 0)) {
			proc_fdunlock(p);
			return (error);
		} else if (!file_issendable(p, tmpfp)) {
			proc_fdunlock(p);
			return (EINVAL);
		} else if (FP_ISGUARDED(tmpfp, GUARD_SOCKET_IPC)) {
			error = fp_guard_exception(p,
				fds[i], tmpfp, kGUARD_EXC_SOCKET_IPC);
			proc_fdunlock(p);
			return (error);
		}
	}
	rp = (struct fileglob **)(cm + 1);

	/* On K64 we need to walk backwards because a fileglob * is twice the size of an fd 
	 * and doing them in-order would result in stomping over unprocessed fd's
	 */
	for (i = (oldfds - 1); i >= 0; i--) {
		(void) fdgetf_noref(p, fds[i], &fp);
		if (fg_insertuipc_mark(fp->f_fglob))
			fg_ins[i / 8] |= 0x80 >> (i % 8);
		rp[i] = fp->f_fglob;
	}
	proc_fdunlock(p);

	for (i = 0; i < oldfds; i++) {
		if (fg_ins[i / 8] & (0x80 >> (i % 8))) {
			VERIFY(rp[i]->fg_lflags & FG_INSMSGQ);
			fg_insertuipc(rp[i]);
		}
		(void) OSAddAtomic(1, &unp_rights);
	}

	return (0);
}

static int	unp_defer, unp_gcing, unp_gcwait;
static thread_t unp_gcthread = NULL;

/* always called under uipc_lock */
void
unp_gc_wait(void)
{
	if (unp_gcthread == current_thread())
		return;

	while (unp_gcing != 0) {
		unp_gcwait = 1;
		msleep(&unp_gcing, uipc_lock, 0 , "unp_gc_wait", NULL);
	}
}


__private_extern__ void
unp_gc(void)
{
	struct fileglob *fg, *nextfg;
	struct socket *so;
	static struct fileglob **extra_ref;
	struct fileglob **fpp;
	int nunref, i;
	int need_gcwakeup = 0;

	lck_mtx_lock(uipc_lock);
	if (unp_gcing) {
		lck_mtx_unlock(uipc_lock);
		return;
	}
	unp_gcing = 1;
	unp_defer = 0;
	unp_gcthread = current_thread();
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
		for (fg = fmsghead.lh_first; fg != 0;
		    fg = fg->f_msglist.le_next) {
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
				if (fg->fg_flag & FMARK) {
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
			if (FILEGLOB_DTYPE(fg) != DTYPE_SOCKET ||
			    (so = (struct socket *)fg->fg_data) == 0) {
				lck_mtx_unlock(&fg->fg_lock);
				continue;
			}
			if (so->so_proto->pr_domain != localdomain ||
			    (so->so_proto->pr_flags&PR_RIGHTS) == 0) {
				lck_mtx_unlock(&fg->fg_lock);
				continue;
			}
#ifdef notdef
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
			 *
			 * In case a file is passed onto itself we need to 
			 * release the file lock.
			 */
			lck_mtx_unlock(&fg->fg_lock);

			unp_scan(so->so_rcv.sb_mb, unp_mark, 0);
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
	extra_ref = _MALLOC(nfiles * sizeof (struct fileglob *),
	    M_FILEGLOB, M_WAITOK);
	if (extra_ref == NULL)
		goto bail;
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

		if (FILEGLOB_DTYPE(tfg) == DTYPE_SOCKET &&
		    tfg->fg_data != NULL) {
			so = (struct socket *)(tfg->fg_data);

			socket_lock(so, 0);
			
			sorflush(so);

			socket_unlock(so, 0);
		}
	}
	for (i = nunref, fpp = extra_ref; --i >= 0; ++fpp)
		closef_locked((struct fileproc *)0, *fpp, (proc_t)NULL);

	FREE((caddr_t)extra_ref, M_FILEGLOB);
bail:
        lck_mtx_lock(uipc_lock);
	unp_gcing = 0;
	unp_gcthread = NULL;

	if (unp_gcwait != 0) {
		unp_gcwait = 0;
		need_gcwakeup = 1;
	}
	lck_mtx_unlock(uipc_lock);

	if (need_gcwakeup != 0)
		wakeup(&unp_gcing);
}

void
unp_dispose(struct mbuf *m)
{
	if (m) {
		unp_scan(m, unp_discard, NULL);
	}
}

/*
 * Returns:	0			Success
 */
static int
unp_listen(struct unpcb *unp, proc_t p)
{
	kauth_cred_t safecred = kauth_cred_proc_ref(p);
	cru2x(safecred, &unp->unp_peercred);
	kauth_cred_unref(&safecred);
	unp->unp_flags |= UNP_HAVEPCCACHED;
	return (0);
}

static void
unp_scan(struct mbuf *m0, void (*op)(struct fileglob *, void *arg), void *arg)
{
	struct mbuf *m;
	struct fileglob **rp;
	struct cmsghdr *cm;
	int i;
	int qfds;

	while (m0) {
		for (m = m0; m; m = m->m_next)
			if (m->m_type == MT_CONTROL &&
			    (size_t)m->m_len >= sizeof (*cm)) {
				cm = mtod(m, struct cmsghdr *);
				if (cm->cmsg_level != SOL_SOCKET ||
				    cm->cmsg_type != SCM_RIGHTS)
					continue;
				qfds = (cm->cmsg_len - sizeof (*cm)) /
				    sizeof (int);
				rp = (struct fileglob **)(cm + 1);
				for (i = 0; i < qfds; i++)
					(*op)(*rp++, arg);
				break;		/* XXX, but saves time */
			}
		m0 = m0->m_act;
	}
}

static void
unp_mark(struct fileglob *fg, __unused void *arg)
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

static void
unp_discard(struct fileglob *fg, void *p)
{
	if (p == NULL)
		p = current_proc();		/* XXX */

	(void) OSAddAtomic(1, &unp_disposed);
	if (fg_removeuipc_mark(fg)) {
		VERIFY(fg->fg_lflags & FG_RMMSGQ);
		fg_removeuipc(fg);
	}
	(void) OSAddAtomic(-1, &unp_rights);

	proc_fdlock(p);
	(void) closef_locked((struct fileproc *)0, fg, p);
	proc_fdunlock(p);
}

int
unp_lock(struct socket *so, int refcount, void * lr)
 {
        void * lr_saved;
        if (lr == 0)
                lr_saved = (void *)  __builtin_return_address(0);
        else lr_saved = lr;

        if (so->so_pcb) {
                lck_mtx_lock(&((struct unpcb *)so->so_pcb)->unp_mtx);
        } else  {
                panic("unp_lock: so=%p NO PCB! lr=%p ref=0x%x\n", 
			so, lr_saved, so->so_usecount);
        }

        if (so->so_usecount < 0)
                panic("unp_lock: so=%p so_pcb=%p lr=%p ref=0x%x\n",
                so, so->so_pcb, lr_saved, so->so_usecount);

        if (refcount) {
		VERIFY(so->so_usecount > 0);
		so->so_usecount++;
	}
        so->lock_lr[so->next_lock_lr] = lr_saved;
        so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
        return (0);
}

int
unp_unlock(struct socket *so, int refcount, void * lr)
{
        void * lr_saved;
        lck_mtx_t * mutex_held = NULL;
	struct unpcb *unp = sotounpcb(so);

        if (lr == 0)
                lr_saved = (void *) __builtin_return_address(0);
        else lr_saved = lr;

        if (refcount)
                so->so_usecount--;

        if (so->so_usecount < 0)
                panic("unp_unlock: so=%p usecount=%x\n", so, so->so_usecount);
        if (so->so_pcb == NULL) {
                panic("unp_unlock: so=%p NO PCB usecount=%x\n", so, so->so_usecount);
        } else {
                mutex_held = &((struct unpcb *)so->so_pcb)->unp_mtx;
        }
        lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
        so->unlock_lr[so->next_unlock_lr] = lr_saved;
        so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;

        if (so->so_usecount == 0 && (so->so_flags & SOF_PCBCLEARING)) {
		sofreelastref(so, 1);

		if (unp->unp_addr)
			FREE(unp->unp_addr, M_SONAME);
		
		lck_mtx_unlock(mutex_held);

		lck_mtx_destroy(&unp->unp_mtx, unp_mtx_grp);
		zfree(unp_zone, unp);

		unp_gc();
	} else {
		lck_mtx_unlock(mutex_held);
	}

        return (0);
}

lck_mtx_t *
unp_getlock(struct socket *so, __unused int locktype)
{
        struct unpcb *unp = (struct unpcb *)so->so_pcb;


        if (so->so_pcb)  {
                if (so->so_usecount < 0)
                        panic("unp_getlock: so=%p usecount=%x\n", so, so->so_usecount);
                return(&unp->unp_mtx);
        } else {
                panic("unp_getlock: so=%p NULL so_pcb\n", so);
                return (so->so_proto->pr_domain->dom_mtx);
        }
}

