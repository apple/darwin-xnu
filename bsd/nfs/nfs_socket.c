/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1989, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs_socket.c	8.5 (Berkeley) 3/30/95
 * FreeBSD-Id: nfs_socket.c,v 1.30 1997/10/28 15:59:07 bde Exp $
 */

/*
 * Socket operations for use by nfs
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/kernel.h>
#include <sys/kpi_mbuf.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/tprintf.h>
#include <sys/uio_internal.h>
#include <libkern/OSAtomic.h>

#include <sys/time.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <sys/user.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>

/* XXX */
boolean_t	current_thread_aborted(void);
kern_return_t	thread_terminate(thread_t);


#if NFSSERVER
int nfsrv_sock_max_rec_queue_length = 128; /* max # RPC records queued on (UDP) socket */

static int nfsrv_getstream(struct nfsrv_sock *,int);
static int nfsrv_getreq(struct nfsrv_descript *);
extern int nfsv3_procid[NFS_NPROCS];
#endif /* NFSSERVER */

#if NFSCLIENT

static int	nfs_connect_setup(struct nfsmount *);
static void	nfs_reqdequeue(struct nfsreq *);
static void	nfs_udp_rcv(socket_t, void*, int);
static void	nfs_tcp_rcv(socket_t, void*, int);
static void	nfs_request_match_reply(struct nfsmount *, mbuf_t);
static void	nfs_softterm(struct nfsreq *);

#ifdef NFS_SOCKET_DEBUGGING
#define NFS_SOCK_DBG(X)	printf X
#else
#define NFS_SOCK_DBG(X)
#endif

/*
 * Estimate rto for an nfs rpc sent via. an unreliable datagram.
 * Use the mean and mean deviation of rtt for the appropriate type of rpc
 * for the frequent rpcs and a default for the others.
 * The justification for doing "other" this way is that these rpcs
 * happen so infrequently that timer est. would probably be stale.
 * Also, since many of these rpcs are
 * non-idempotent, a conservative timeout is desired.
 * getattr, lookup - A+2D
 * read, write     - A+4D
 * other	   - nm_timeo
 */
#define	NFS_RTO(n, t) \
	((t) == 0 ? (n)->nm_timeo : \
	 ((t) < 3 ? \
	  (((((n)->nm_srtt[t-1] + 3) >> 2) + (n)->nm_sdrtt[t-1] + 1) >> 1) : \
	  ((((n)->nm_srtt[t-1] + 7) >> 3) + (n)->nm_sdrtt[t-1] + 1)))
#define	NFS_SRTT(r)	(r)->r_nmp->nm_srtt[proct[(r)->r_procnum] - 1]
#define	NFS_SDRTT(r)	(r)->r_nmp->nm_sdrtt[proct[(r)->r_procnum] - 1]

/*
 * Defines which timer to use for the procnum.
 * 0 - default
 * 1 - getattr
 * 2 - lookup
 * 3 - read
 * 4 - write
 */
static int proct[NFS_NPROCS] = {
	0, 1, 0, 2, 1, 3, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0
};

/*
 * There is a congestion window for outstanding rpcs maintained per mount
 * point. The cwnd size is adjusted in roughly the way that:
 * Van Jacobson, Congestion avoidance and Control, In "Proceedings of
 * SIGCOMM '88". ACM, August 1988.
 * describes for TCP. The cwnd size is chopped in half on a retransmit timeout
 * and incremented by 1/cwnd when each rpc reply is received and a full cwnd
 * of rpcs is in progress.
 * (The sent count and cwnd are scaled for integer arith.)
 * Variants of "slow start" were tried and were found to be too much of a
 * performance hit (ave. rtt 3 times larger),
 * I suspect due to the large rtt that nfs rpcs have.
 */
#define	NFS_CWNDSCALE	256
#define	NFS_MAXCWND	(NFS_CWNDSCALE * 32)
static int nfs_backoff[8] = { 2, 4, 8, 16, 32, 64, 128, 256, };

/*
 * Initialize socket state and perform setup for a new NFS connection.
 */
int
nfs_connect(struct nfsmount *nmp)
{
	socket_t so;
	int error, on = 1, proto;
	sock_upcall upcall;
	struct sockaddr *saddr;
	struct sockaddr_in sin;
	struct timeval timeo;
	u_short tport;

	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_sockflags |= NMSOCK_CONNECTING;
	saddr = mbuf_data(nmp->nm_nam);
	upcall = (nmp->nm_sotype == SOCK_STREAM) ? nfs_tcp_rcv : nfs_udp_rcv;
	lck_mtx_unlock(&nmp->nm_lock);
	error = sock_socket(saddr->sa_family, nmp->nm_sotype,
			    nmp->nm_soproto, upcall, nmp, &nmp->nm_so);
	if (error)
		goto bad;
	lck_mtx_lock(&nmp->nm_lock);
	so = nmp->nm_so;

	/*
	 * Some servers require that the client port be a reserved port number.
	 */
	if (saddr->sa_family == AF_INET && (nmp->nm_flag & NFSMNT_RESVPORT)) {
		lck_mtx_unlock(&nmp->nm_lock);
		sin.sin_len = sizeof (struct sockaddr_in);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		tport = IPPORT_RESERVED - 1;
		sin.sin_port = htons(tport);
		while (((error = sock_bind(so, (struct sockaddr *) &sin)) == EADDRINUSE) &&
		       (--tport > IPPORT_RESERVED / 2))
			sin.sin_port = htons(tport);
		if (error)
			goto bad;
		lck_mtx_lock(&nmp->nm_lock);
	}

	/*
	 * Protocols that do not require connections may be optionally left
	 * unconnected for servers that reply from a different address/port.
	 */
	if (nmp->nm_flag & NFSMNT_NOCONN) {
		if (nmp->nm_sotype == SOCK_STREAM) {
			error = ENOTCONN;
			lck_mtx_unlock(&nmp->nm_lock);
			goto bad;
		}
	} else {
		int tocnt = 0, optlen = sizeof(error);
		struct timespec ts = { 2, 0 };

		lck_mtx_unlock(&nmp->nm_lock);
		error = sock_connect(so, mbuf_data(nmp->nm_nam), MSG_DONTWAIT);
		if (error && (error != EINPROGRESS))
			goto bad;
		lck_mtx_lock(&nmp->nm_lock);
		while (!sock_isconnected(so)) {
			if (tocnt++ == 15) /* log a warning if connect is taking a while */
				log(LOG_INFO, "nfs_connect: socket connect taking a while for %s\n",
					vfs_statfs(nmp->nm_mountp)->f_mntfromname);
			/* check for error on socket */
			sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &error, &optlen);
			if (error) {
				log(LOG_INFO, "nfs_connect: socket error %d for %s\n",
					error, vfs_statfs(nmp->nm_mountp)->f_mntfromname);
				break;
			}
			if (tocnt > 60) {
				/* abort if this is taking too long */
				error = ENOTCONN;
				break;
			}
			if ((error = nfs_sigintr(nmp, NULL, current_thread(), 1)))
				break;
			msleep(&nmp->nm_so, &nmp->nm_lock, PSOCK, "nfs_socket_connect", &ts);
		}
		if (tocnt > 15)
			log(LOG_INFO, "nfs_connect: socket connect %s for %s\n",
				error ? "aborted" : "completed",
				vfs_statfs(nmp->nm_mountp)->f_mntfromname);
		if (error) {
			lck_mtx_unlock(&nmp->nm_lock);
			goto bad;
		}
	}

	/*
	 * Set socket send/receive timeouts
	 * - Receive timeout shouldn't matter because all receives are performed
	 *   in the socket upcall non-blocking.
	 * - Send timeout should allow us to react to a blocked socket.
	 *   Soft mounts will want to abort sooner.
	 */
	timeo.tv_usec = 0;
	timeo.tv_sec = (nmp->nm_flag & NFSMNT_SOFT) ? 10 : 60;
	error |= sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
	error |= sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
	if (error) {
		log(LOG_INFO, "nfs_connect: socket timeout setting errors for %s\n",
			vfs_statfs(nmp->nm_mountp)->f_mntfromname);
		error = 0;
	}

	if (nmp->nm_sotype == SOCK_STREAM) {
		/* Assume that SOCK_STREAM always requires a connection */
		sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
		/* set nodelay for TCP */
		sock_gettype(so, NULL, NULL, &proto);
		if (proto == IPPROTO_TCP)
			sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}

	if (nmp->nm_sotype == SOCK_DGRAM) { /* set socket buffer sizes for UDP */
		int reserve = NFS_UDPSOCKBUF;
		error |= sock_setsockopt(so, SOL_SOCKET, SO_SNDBUF, &reserve, sizeof(reserve));
		error |= sock_setsockopt(so, SOL_SOCKET, SO_RCVBUF, &reserve, sizeof(reserve));
		if (error) {
			log(LOG_INFO, "nfs_connect: socket buffer setting errors for %s\n",
				vfs_statfs(nmp->nm_mountp)->f_mntfromname);
			error = 0;
		}
	}

	/* set SO_NOADDRERR to detect network changes ASAP */
	error = sock_setsockopt(so, SOL_SOCKET, SO_NOADDRERR, &on, sizeof(on));
	if (error) {
		lck_mtx_unlock(&nmp->nm_lock);
		goto bad;
	}

	if (!(nmp->nm_flag & NFSMNT_INT))
		sock_nointerrupt(so, 1);

	/* Initialize socket state variables */
	nmp->nm_srtt[0] = nmp->nm_srtt[1] = nmp->nm_srtt[2] =
		nmp->nm_srtt[3] = (NFS_TIMEO << 3);
	nmp->nm_sdrtt[0] = nmp->nm_sdrtt[1] = nmp->nm_sdrtt[2] =
		nmp->nm_sdrtt[3] = 0;
	if (nmp->nm_sotype == SOCK_DGRAM) {
		/* XXX do we really want to reset this on each reconnect? */
		nmp->nm_cwnd = NFS_MAXCWND / 2;	    /* Initial send window */
		nmp->nm_sent = 0;
	} else if (nmp->nm_sotype == SOCK_STREAM) {
		nmp->nm_markerleft = sizeof(nmp->nm_fragleft);
		nmp->nm_fragleft = nmp->nm_reclen = 0;
		nmp->nm_timeouts = 0;
	}
	nmp->nm_sockflags &= ~NMSOCK_CONNECTING;
	nmp->nm_sockflags |= NMSOCK_SETUP;
	FSDBG(529, nmp, nmp->nm_state, nmp->nm_flag, nmp->nm_cwnd);
	lck_mtx_unlock(&nmp->nm_lock);
	error = nfs_connect_setup(nmp);
bad:
	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_sockflags &= ~(NMSOCK_CONNECTING|NMSOCK_SETUP);
	if (!error) {
		nmp->nm_sockflags |= NMSOCK_READY;
		wakeup(&nmp->nm_sockflags);
	}
	lck_mtx_unlock(&nmp->nm_lock);
	if (error)
		nfs_disconnect(nmp);
	return (error);
}

/* setup & confirm socket connection is functional */
static int
nfs_connect_setup(struct nfsmount *nmp)
{
	struct nfsm_chain nmreq, nmrep;
	int error = 0, status;
	u_int64_t xid;

	if (nmp->nm_vers >= NFS_VER4) {
		error = nfs4_setclientid(nmp);
	} else {
		/* verify connection's OK by sending a NULL request */
		nfsm_chain_null(&nmreq);
		nfsm_chain_null(&nmrep);
		nfsm_chain_build_alloc_init(error, &nmreq, 0);
		nfsm_chain_build_done(error, &nmreq);
		nfsmout_if(error);
		error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC_NULL,
				current_thread(), NULL, R_SETUP, &nmrep, &xid, &status);
		if (!error)
			error = status;
nfsmout:
		nfsm_chain_cleanup(&nmreq);
		nfsm_chain_cleanup(&nmrep);
	}
	return (error);
}

/*
 * NFS socket reconnect routine:
 * Called when a connection is broken.
 * - disconnect the old socket
 * - nfs_connect() again
 * - set R_MUSTRESEND for all outstanding requests on mount point
 * If this fails the mount point is DEAD!
 */
static int
nfs_reconnect(struct nfsmount *nmp)
{
	struct nfsreq *rq;
	struct timeval now;
	thread_t thd = current_thread();
	int error, lastmsg, wentdown = 0;

	microuptime(&now);
	lastmsg = now.tv_sec - (nmp->nm_tprintf_delay - nmp->nm_tprintf_initial_delay);

	nfs_disconnect(nmp);

	while ((error = nfs_connect(nmp))) {
		if (error == EINTR || error == ERESTART)
			return (EINTR);
		if (error == EIO)
			return (EIO);
		microuptime(&now);
		if ((lastmsg + nmp->nm_tprintf_delay) < now.tv_sec) {
			lastmsg = now.tv_sec;
			nfs_down(nmp, thd, error, NFSSTA_TIMEO, "can not connect");
			wentdown = 1;
		}
		lck_mtx_lock(&nmp->nm_lock);
		if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
			/* we're not yet completely mounted and */
			/* we can't reconnect, so we fail */
			lck_mtx_unlock(&nmp->nm_lock);
			return (error);
		}
		if ((error = nfs_sigintr(nmp, NULL, thd, 1))) {
			lck_mtx_unlock(&nmp->nm_lock);
			return (error);
		}
		lck_mtx_unlock(&nmp->nm_lock);
		tsleep(&lbolt, PSOCK, "nfs_reconnect_delay", 0);
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			return (error);
	}

	if (wentdown)
		nfs_up(nmp, thd, NFSSTA_TIMEO, "connected");

	/*
	 * Loop through outstanding request list and mark all requests
	 * as needing a resend.  (Though nfs_need_reconnect() probably
	 * marked them all already.)
	 */
	lck_mtx_lock(nfs_request_mutex);
	TAILQ_FOREACH(rq, &nfs_reqq, r_chain) {
		if (rq->r_nmp == nmp) {
			lck_mtx_lock(&rq->r_mtx);
			if (!rq->r_error && !rq->r_nmrep.nmc_mhead && !(rq->r_flags & R_MUSTRESEND)) {
				rq->r_flags |= R_MUSTRESEND;
				rq->r_rtt = -1;
				wakeup(rq);
				if ((rq->r_flags & (R_ASYNC|R_ASYNCWAIT)) == R_ASYNC)
					nfs_asyncio_resend(rq);
			}
			lck_mtx_unlock(&rq->r_mtx);
		}
	}
	lck_mtx_unlock(nfs_request_mutex);
	return (0);
}

/*
 * NFS disconnect. Clean up and unlink.
 */
void
nfs_disconnect(struct nfsmount *nmp)
{
	socket_t so;

	lck_mtx_lock(&nmp->nm_lock);
	if ((nmp->nm_sotype == SOCK_STREAM) && nmp->nm_m) {
		mbuf_freem(nmp->nm_m);
		nmp->nm_m = nmp->nm_mlast = NULL;
	}
	if (nmp->nm_so) {
		so = nmp->nm_so;
		nmp->nm_so = NULL;
		lck_mtx_unlock(&nmp->nm_lock);
		sock_shutdown(so, SHUT_RDWR);
		sock_close(so);
	} else {
		lck_mtx_unlock(&nmp->nm_lock);
	}
}

/*
 * mark an NFS mount as needing a reconnect/resends.
 */
static void
nfs_need_reconnect(struct nfsmount *nmp)
{
	struct nfsreq *rq;

	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_sockflags &= ~(NMSOCK_READY|NMSOCK_SETUP);
	lck_mtx_unlock(&nmp->nm_lock);

	/*
	 * Loop through outstanding request list and
	 * mark all requests as needing a resend.
	 */
	lck_mtx_lock(nfs_request_mutex);
	TAILQ_FOREACH(rq, &nfs_reqq, r_chain) {
		if (rq->r_nmp == nmp) {
			lck_mtx_lock(&rq->r_mtx);
			if (!rq->r_error && !rq->r_nmrep.nmc_mhead && !(rq->r_flags & R_MUSTRESEND)) {
				rq->r_flags |= R_MUSTRESEND;
				rq->r_rtt = -1;
				wakeup(rq);
				if ((rq->r_flags & (R_ASYNC|R_ASYNCWAIT)) == R_ASYNC)
					nfs_asyncio_resend(rq);
			}
			lck_mtx_unlock(&rq->r_mtx);
		}
	}
	lck_mtx_unlock(nfs_request_mutex);
}

/*
 * thread to handle miscellaneous async NFS socket work (reconnects/resends)
 */
static void
nfs_mount_sock_thread(void *arg, __unused wait_result_t wr)
{
	struct nfsmount *nmp = arg;
	struct timespec ts = { 30, 0 };
	thread_t thd = current_thread();
	struct nfsreq *req;
	struct timeval now;
	int error, dofinish, force;

	lck_mtx_lock(&nmp->nm_lock);

	while (!(nmp->nm_sockflags & NMSOCK_READY) || !TAILQ_EMPTY(&nmp->nm_resendq)) {
		if (nmp->nm_sockflags & NMSOCK_UNMOUNT)
			break;
		force = (nmp->nm_state & NFSSTA_FORCE);
		/* do reconnect, if necessary */
		if (!(nmp->nm_sockflags & NMSOCK_READY) && !force) {
			if (nmp->nm_reconnect_start <= 0) {
				microuptime(&now);
				nmp->nm_reconnect_start = now.tv_sec;
			}
			lck_mtx_unlock(&nmp->nm_lock);
			NFS_SOCK_DBG(("nfs reconnect %s\n", vfs_statfs(nmp->nm_mountp)->f_mntfromname));
			if ((error = nfs_reconnect(nmp)))
				printf("nfs_reconnect failed %d for %s\n", error,
					vfs_statfs(nmp->nm_mountp)->f_mntfromname);
			else
				nmp->nm_reconnect_start = 0;
			lck_mtx_lock(&nmp->nm_lock);
		}
		/* do resends, if necessary/possible */
		while (((nmp->nm_sockflags & NMSOCK_READY) || force) && ((req = TAILQ_FIRST(&nmp->nm_resendq)))) {
			if (req->r_resendtime)
				microuptime(&now);
			while (req && !force && req->r_resendtime && (now.tv_sec < req->r_resendtime))
				req = TAILQ_NEXT(req, r_rchain);
			if (!req)
				break;
			TAILQ_REMOVE(&nmp->nm_resendq, req, r_rchain);
			req->r_rchain.tqe_next = NFSREQNOLIST;
			lck_mtx_unlock(&nmp->nm_lock);
			lck_mtx_lock(&req->r_mtx);
			if (req->r_error || req->r_nmrep.nmc_mhead) {
				dofinish = req->r_callback.rcb_func && !(req->r_flags & R_WAITSENT);
				req->r_flags &= ~R_RESENDQ;
				wakeup(req);
				lck_mtx_unlock(&req->r_mtx);
				if (dofinish)
					nfs_asyncio_finish(req);
				lck_mtx_lock(&nmp->nm_lock);
				continue;
			}
			if ((req->r_flags & R_RESTART) || req->r_gss_ctx) {
				req->r_flags &= ~R_RESTART;
				req->r_resendtime = 0;
				lck_mtx_unlock(&req->r_mtx);
				/* async RPCs on GSS mounts need to be rebuilt and resent. */
				nfs_reqdequeue(req);
				if (req->r_gss_ctx) {
					nfs_gss_clnt_rpcdone(req);
					error = nfs_gss_clnt_args_restore(req);
					if (error == ENEEDAUTH)
						req->r_xid = 0;
				}
				NFS_SOCK_DBG(("nfs async%s restart: p %d x 0x%llx f 0x%x rtt %d\n",
					req->r_gss_ctx ? " gss" : "", req->r_procnum, req->r_xid,
					req->r_flags, req->r_rtt));
				error = !req->r_nmp ? ENXIO : 0;	/* unmounted? */
				if (!error)
					error = nfs_sigintr(nmp, req, req->r_thread, 0);
				if (!error)
					error = nfs_request_add_header(req);
				if (!error)
					error = nfs_request_send(req, 0);
				lck_mtx_lock(&req->r_mtx);
				if (req->r_rchain.tqe_next == NFSREQNOLIST)
					req->r_flags &= ~R_RESENDQ;
				if (error)
					req->r_error = error;
				wakeup(req);
				dofinish = error && req->r_callback.rcb_func && !(req->r_flags & R_WAITSENT);
				lck_mtx_unlock(&req->r_mtx);
				if (dofinish)
					nfs_asyncio_finish(req);
				lck_mtx_lock(&nmp->nm_lock);
				error = 0;
				continue;
			}
			NFS_SOCK_DBG(("nfs async resend: p %d x 0x%llx f 0x%x rtt %d\n",
				req->r_procnum, req->r_xid, req->r_flags, req->r_rtt));
			error = !req->r_nmp ? ENXIO : 0;	/* unmounted? */
			if (!error)
				error = nfs_sigintr(nmp, req, req->r_thread, 0);
			if (!error) {
				lck_mtx_unlock(&req->r_mtx);
				error = nfs_send(req, 0);
				lck_mtx_lock(&req->r_mtx);
				if (!error) {
					if (req->r_rchain.tqe_next == NFSREQNOLIST)
						req->r_flags &= ~R_RESENDQ;
					wakeup(req);
					lck_mtx_unlock(&req->r_mtx);
					lck_mtx_lock(&nmp->nm_lock);
					continue;
				}
			}
			req->r_error = error;
			if (req->r_rchain.tqe_next == NFSREQNOLIST)
				req->r_flags &= ~R_RESENDQ;
			wakeup(req);
			dofinish = req->r_callback.rcb_func && !(req->r_flags & R_WAITSENT);
			lck_mtx_unlock(&req->r_mtx);
			if (dofinish)
				nfs_asyncio_finish(req);
			lck_mtx_lock(&nmp->nm_lock);
		}
		if (nmp->nm_sockflags & NMSOCK_READY) {
			ts.tv_sec = TAILQ_EMPTY(&nmp->nm_resendq) ? 30 : 1;
			msleep(&nmp->nm_sockthd, &nmp->nm_lock, PSOCK, "nfssockthread", &ts);
		} else if (force)
			break;
	}

	if (nmp->nm_sockthd == thd)
		nmp->nm_sockthd = NULL;
	lck_mtx_unlock(&nmp->nm_lock);
	wakeup(&nmp->nm_sockthd);
	thread_terminate(thd);
}

/* start or wake a mount's socket thread */
void
nfs_mount_sock_thread_wake(struct nfsmount *nmp)
{
	if (nmp->nm_sockthd)
		wakeup(&nmp->nm_sockthd);
	else if (kernel_thread_start(nfs_mount_sock_thread, nmp, &nmp->nm_sockthd) == KERN_SUCCESS)
		thread_deallocate(nmp->nm_sockthd);
}

/*
 * The NFS client send routine.
 *
 * Send the given NFS request out the mount's socket.
 * Holds nfs_sndlock() for the duration of this call.
 *
 * - check for request termination (sigintr)
 * - perform reconnect, if necessary
 * - UDP: check the congestion window
 * - make a copy of the request to send
 * - UDP: update the congestion window
 * - send the request
 *
 * If sent successfully, R_MUSTRESEND and R_RESENDERR are cleared.
 * rexmit count is also updated if this isn't the first send.
 *
 * If the send is not successful, make sure R_MUSTRESEND is set.
 * If this wasn't the first transmit, set R_RESENDERR.
 * Also, undo any UDP congestion window changes made.
 *
 * If the error appears to indicate that the socket should
 * be reconnected, mark the socket for reconnection.
 *
 * Only return errors when the request should be aborted.
 */
int
nfs_send(struct nfsreq *req, int wait)
{
	struct nfsmount *nmp;
	socket_t so;
	int error, error2, sotype, rexmit, slpflag = 0, needrecon;
	struct msghdr msg;
	struct sockaddr *sendnam;
	mbuf_t mreqcopy;
	size_t sentlen = 0;
	struct timespec ts = { 2, 0 };

again:
	error = nfs_sndlock(req);
	if (error)
		return (error);

	error = nfs_sigintr(req->r_nmp, req, req->r_thread, 0);
	if (error) {
		nfs_sndunlock(req);
		return (error);
	}
	nmp = req->r_nmp;
	sotype = nmp->nm_sotype;

	if ((req->r_flags & R_SETUP) && !(nmp->nm_sockflags & NMSOCK_SETUP)) {
		/* a setup RPC but we're not in SETUP... must need reconnect */
		nfs_sndunlock(req);
		return (EPIPE);
	}

	/* If the socket needs reconnection, do that now. */
	/* wait until socket is ready - unless this request is part of setup */
	lck_mtx_lock(&nmp->nm_lock);
	if (!(nmp->nm_sockflags & NMSOCK_READY) &&
	    !((nmp->nm_sockflags & NMSOCK_SETUP) && (req->r_flags & R_SETUP))) {
		if (nmp->nm_flag & NFSMNT_INT)
			slpflag |= PCATCH;
		lck_mtx_unlock(&nmp->nm_lock);
		nfs_sndunlock(req);
		if (!wait) {
			lck_mtx_lock(&req->r_mtx);
			req->r_flags |= R_MUSTRESEND;
			req->r_rtt = 0;
			lck_mtx_unlock(&req->r_mtx);
			return (0);
		}
		NFS_SOCK_DBG(("nfs_send: 0x%llx wait reconnect\n", req->r_xid));
		lck_mtx_lock(&req->r_mtx);
		req->r_flags &= ~R_MUSTRESEND;
		req->r_rtt = 0;
		lck_mtx_unlock(&req->r_mtx);
		lck_mtx_lock(&nmp->nm_lock);
		while (!(nmp->nm_sockflags & NMSOCK_READY)) {
			/* don't bother waiting if the socket thread won't be reconnecting it */
			if (nmp->nm_state & NFSSTA_FORCE) {
				error = EIO;
				break;
			}
			/* make sure socket thread is running, then wait */
			nfs_mount_sock_thread_wake(nmp);
			if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 1)))
				break;
			msleep(req, &nmp->nm_lock, slpflag|PSOCK, "nfsconnectwait", &ts);
			slpflag = 0;
		}
		lck_mtx_unlock(&nmp->nm_lock);
		if (error)
			return (error);
		goto again;
	}
	so = nmp->nm_so;
	lck_mtx_unlock(&nmp->nm_lock);
	if (!so) {
		nfs_sndunlock(req);
		lck_mtx_lock(&req->r_mtx);
		req->r_flags |= R_MUSTRESEND;
		req->r_rtt = 0;
		lck_mtx_unlock(&req->r_mtx);
		return (0);
	}

	lck_mtx_lock(&req->r_mtx);
	rexmit = (req->r_flags & R_SENT);

	if (sotype == SOCK_DGRAM) {
		lck_mtx_lock(&nmp->nm_lock);
		if (!(req->r_flags & R_CWND) && (nmp->nm_sent >= nmp->nm_cwnd)) {
			/* if we can't send this out yet, wait on the cwnd queue */
			slpflag = ((nmp->nm_flag & NFSMNT_INT) && req->r_thread) ? PCATCH : 0;
			lck_mtx_unlock(&nmp->nm_lock);
			nfs_sndunlock(req);
			req->r_flags |= R_MUSTRESEND;
			lck_mtx_unlock(&req->r_mtx);
			if (!wait) {
				req->r_rtt = 0;
				return (0);
			}
			lck_mtx_lock(&nmp->nm_lock);
			while (nmp->nm_sent >= nmp->nm_cwnd) {
				if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 1)))
					break;
				TAILQ_INSERT_TAIL(&nmp->nm_cwndq, req, r_cchain);
				msleep(req, &nmp->nm_lock, slpflag | (PZERO - 1), "nfswaitcwnd", &ts);
				slpflag = 0;
				if ((req->r_cchain.tqe_next != NFSREQNOLIST)) {
					TAILQ_REMOVE(&nmp->nm_cwndq, req, r_cchain);
					req->r_cchain.tqe_next = NFSREQNOLIST;
				}
			}
			lck_mtx_unlock(&nmp->nm_lock);
			goto again;
		}
		/*
		 * We update these *before* the send to avoid racing
		 * against others who may be looking to send requests.
		 */
		if (!rexmit) {
			/* first transmit */
			req->r_flags |= R_CWND;
			nmp->nm_sent += NFS_CWNDSCALE;
		} else {
			/*
			 * When retransmitting, turn timing off
			 * and divide congestion window by 2. 
			 */
			req->r_flags &= ~R_TIMING;
			nmp->nm_cwnd >>= 1;
			if (nmp->nm_cwnd < NFS_CWNDSCALE)
				nmp->nm_cwnd = NFS_CWNDSCALE;
		}
		lck_mtx_unlock(&nmp->nm_lock);
	}

	req->r_flags &= ~R_MUSTRESEND;
	lck_mtx_unlock(&req->r_mtx);

	error = mbuf_copym(req->r_mhead, 0, MBUF_COPYALL,
			wait ? MBUF_WAITOK : MBUF_DONTWAIT, &mreqcopy);
	if (error) {
		if (wait)
			log(LOG_INFO, "nfs_send: mbuf copy failed %d\n", error);
		nfs_sndunlock(req);
		lck_mtx_lock(&req->r_mtx);
		req->r_flags |= R_MUSTRESEND;
		req->r_rtt = 0;
		lck_mtx_unlock(&req->r_mtx);
		return (0);
	}

	bzero(&msg, sizeof(msg));
	if (nmp->nm_nam && (sotype != SOCK_STREAM) && !sock_isconnected(so)) {
		if ((sendnam = mbuf_data(nmp->nm_nam))) {
			msg.msg_name = (caddr_t)sendnam;
			msg.msg_namelen = sendnam->sa_len;
		}
	}
	error = sock_sendmbuf(so, &msg, mreqcopy, 0, &sentlen);
#ifdef NFS_SOCKET_DEBUGGING
	if (error || (sentlen != req->r_mreqlen))
		NFS_SOCK_DBG(("nfs_send: 0x%llx sent %d/%d error %d\n",
			req->r_xid, (int)sentlen, (int)req->r_mreqlen, error));
#endif
	if (!error && (sentlen != req->r_mreqlen))
		error = EWOULDBLOCK;
	needrecon = ((sotype == SOCK_STREAM) && sentlen && (sentlen != req->r_mreqlen));

	lck_mtx_lock(&req->r_mtx);
	req->r_rtt = 0;
	if (rexmit && (++req->r_rexmit > NFS_MAXREXMIT))
		req->r_rexmit = NFS_MAXREXMIT;

	if (!error) {
		/* SUCCESS */
		req->r_flags &= ~R_RESENDERR;
		if (rexmit)
			OSAddAtomic(1, (SInt32*)&nfsstats.rpcretries);
		req->r_flags |= R_SENT;
		if (req->r_flags & R_WAITSENT) {
			req->r_flags &= ~R_WAITSENT;
			wakeup(req);
		}
		nfs_sndunlock(req);
		lck_mtx_unlock(&req->r_mtx);
		return (0);
	}

	/* send failed */
	req->r_flags |= R_MUSTRESEND;
	if (rexmit)
		req->r_flags |= R_RESENDERR;
	if ((error == EINTR) || (error == ERESTART))
		req->r_error = error;
	lck_mtx_unlock(&req->r_mtx);

	if (sotype == SOCK_DGRAM) {
		/*
		 * Note: even though a first send may fail, we consider
		 * the request sent for congestion window purposes.
		 * So we don't need to undo any of the changes made above.
		 */
		/*
		 * Socket errors ignored for connectionless sockets??
		 * For now, ignore them all
		 */
		if ((error != EINTR) && (error != ERESTART) &&
		    (error != EWOULDBLOCK) && (error != EIO)) {
			int clearerror = 0, optlen = sizeof(clearerror);
			sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &clearerror, &optlen);
#ifdef NFS_SOCKET_DEBUGGING
			if (clearerror)
				NFS_SOCK_DBG(("nfs_send: ignoring UDP socket error %d so %d\n",
					error, clearerror));
#endif
		}
	}

	/* check if it appears we should reconnect the socket */
	switch (error) {
	case EWOULDBLOCK:
		/* if send timed out, reconnect if on TCP */
		if (sotype != SOCK_STREAM)
			break;
	case EPIPE:
	case EADDRNOTAVAIL:
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case ECONNABORTED:
	case ECONNRESET:
	case ENOTCONN:
	case ESHUTDOWN:
	case ECONNREFUSED:
	case EHOSTDOWN:
	case EHOSTUNREACH:
		needrecon = 1;
		break;
	}
	if (needrecon) { /* mark socket as needing reconnect */
		NFS_SOCK_DBG(("nfs_send: 0x%llx need reconnect %d\n", req->r_xid, error));
		nfs_need_reconnect(nmp);
	}

	nfs_sndunlock(req);

	/*
	 * Don't log some errors:
	 * EPIPE errors may be common with servers that drop idle connections.
	 * EADDRNOTAVAIL may occur on network transitions.
	 * ENOTCONN may occur under some network conditions.
	 */
	if ((error == EPIPE) || (error == EADDRNOTAVAIL) || (error == ENOTCONN))
		error = 0;
	if (error && (error != EINTR) && (error != ERESTART))
		log(LOG_INFO, "nfs send error %d for server %s\n", error,
			!req->r_nmp ? "<unmounted>" :
			vfs_statfs(req->r_nmp->nm_mountp)->f_mntfromname);

	/* prefer request termination error over other errors */
	error2 = nfs_sigintr(req->r_nmp, req, req->r_thread, 0);
	if (error2)
		error = error2;

	/* only allow the following errors to be returned */
	if ((error != EINTR) && (error != ERESTART) && (error != EIO) &&
	    (error != ENXIO) && (error != ETIMEDOUT))
		error = 0;
	return (error);
}

/*
 * NFS client socket upcalls
 *
 * Pull RPC replies out of an NFS mount's socket and match them
 * up with the pending request.
 *
 * The datagram code is simple because we always get whole
 * messages out of the socket.
 *
 * The stream code is more involved because we have to parse
 * the RPC records out of the stream.
 */

/* NFS client UDP socket upcall */
static void
nfs_udp_rcv(socket_t so, void *arg, __unused int waitflag)
{
	struct nfsmount *nmp = arg;
	size_t rcvlen;
	mbuf_t m;
	int error = 0;

	if (nmp->nm_sockflags & NMSOCK_CONNECTING) {
		wakeup(&nmp->nm_so);
		return;
	}

	/* make sure we're on the current socket */
	if (nmp->nm_so != so)
		return;

	do {
		m = NULL;
		rcvlen = 1000000;
		error = sock_receivembuf(so, NULL, &m, MSG_DONTWAIT, &rcvlen);
		if (m)
			nfs_request_match_reply(nmp, m);
	} while (m && !error);

	if (error && (error != EWOULDBLOCK)) {
		/* problems with the socket... mark for reconnection */
		NFS_SOCK_DBG(("nfs_udp_rcv: need reconnect %d\n", error));
		nfs_need_reconnect(nmp);
	}
}

/* NFS client TCP socket upcall */
static void
nfs_tcp_rcv(socket_t so, void *arg, __unused int waitflag)
{
	struct nfsmount *nmp = arg;
	struct iovec_32 aio;
	struct msghdr msg;
	size_t rcvlen;
	mbuf_t m;
	int error = 0;
	int recv;

	if (nmp->nm_sockflags & NMSOCK_CONNECTING) {
		wakeup(&nmp->nm_so);
		return;
	}

	/* make sure we're on the current socket */
	if (nmp->nm_so != so)
		return;

	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_sockflags & NMSOCK_UPCALL) {
		/* upcall is already receiving data - just return */
		lck_mtx_unlock(&nmp->nm_lock);
		return;
	}
	nmp->nm_sockflags |= NMSOCK_UPCALL;

nextfrag:
	recv = 0;

	/* read the TCP RPC record marker */
	while (!error && nmp->nm_markerleft) {
		aio.iov_base = (uintptr_t)((char*)&nmp->nm_fragleft +
				sizeof(nmp->nm_fragleft) - nmp->nm_markerleft);
		aio.iov_len = nmp->nm_markerleft;
		bzero(&msg, sizeof(msg));
		msg.msg_iov = (struct iovec *) &aio;
		msg.msg_iovlen = 1;
		lck_mtx_unlock(&nmp->nm_lock);
		error = sock_receive(so, &msg, MSG_DONTWAIT, &rcvlen);
		lck_mtx_lock(&nmp->nm_lock);
		if (error || !rcvlen)
			break;
		recv = 1;
		nmp->nm_markerleft -= rcvlen;
		if (nmp->nm_markerleft)
			continue;
		/* record marker complete */
		nmp->nm_fragleft = ntohl(nmp->nm_fragleft);
		if (nmp->nm_fragleft & 0x80000000) {
			nmp->nm_sockflags |= NMSOCK_LASTFRAG;
			nmp->nm_fragleft &= ~0x80000000;
		}
		nmp->nm_reclen += nmp->nm_fragleft;
		if (nmp->nm_reclen > NFS_MAXPACKET) {
			/*
			 * This is SERIOUS! We are out of sync with the sender
			 * and forcing a disconnect/reconnect is all I can do.
			 */
			log(LOG_ERR, "%s (%d) from nfs server %s\n",
				"impossible RPC record length", nmp->nm_reclen,
				vfs_statfs(nmp->nm_mountp)->f_mntfromname);
			error = EFBIG;
		}
	}

	/* read the TCP RPC record fragment */
	while (!error && !nmp->nm_markerleft && nmp->nm_fragleft) {
		m = NULL;
		rcvlen = nmp->nm_fragleft;
		lck_mtx_unlock(&nmp->nm_lock);
		error = sock_receivembuf(so, NULL, &m, MSG_DONTWAIT, &rcvlen);
		lck_mtx_lock(&nmp->nm_lock);
		if (error || !rcvlen || !m)
			break;
		recv = 1;
		/* append mbufs to list */
		nmp->nm_fragleft -= rcvlen;
		if (!nmp->nm_m) {
			nmp->nm_m = m;
		} else {
			error = mbuf_setnext(nmp->nm_mlast, m);
			if (error) {
				printf("nfs_tcp_rcv: mbuf_setnext failed %d\n", error);
				mbuf_freem(m);
				break;
			}
		}
		while (mbuf_next(m))
			m = mbuf_next(m);
		nmp->nm_mlast = m;
	}

	/* done reading fragment? */
	m = NULL;
	if (!error && !nmp->nm_markerleft && !nmp->nm_fragleft) {
		/* reset socket fragment parsing state */
		nmp->nm_markerleft = sizeof(nmp->nm_fragleft);
		if (nmp->nm_sockflags & NMSOCK_LASTFRAG) {
			/* RPC record complete */
			m = nmp->nm_m;
			/* reset socket record parsing state */
			nmp->nm_reclen = 0;
			nmp->nm_m = nmp->nm_mlast = NULL;
			nmp->nm_sockflags &= ~NMSOCK_LASTFRAG;
		}
	}

	if (m) { /* match completed response with request */
		lck_mtx_unlock(&nmp->nm_lock);
		nfs_request_match_reply(nmp, m);
		lck_mtx_lock(&nmp->nm_lock);
	}

	/* loop if we've been making error-free progress */
	if (!error && recv)
		goto nextfrag;

	nmp->nm_sockflags &= ~NMSOCK_UPCALL;
	lck_mtx_unlock(&nmp->nm_lock);
#ifdef NFS_SOCKET_DEBUGGING
	if (!recv && (error != EWOULDBLOCK))
		NFS_SOCK_DBG(("nfs_tcp_rcv: got nothing, error %d, got FIN?\n", error));
#endif
	/* note: no error and no data indicates server closed its end */
	if ((error != EWOULDBLOCK) && (error || !recv)) {
		/* problems with the socket... mark for reconnection */
		NFS_SOCK_DBG(("nfs_tcp_rcv: need reconnect %d\n", error));
		nfs_need_reconnect(nmp);
	}
}

/*
 * "poke" a socket to try to provoke any pending errors
 */
static void
nfs_sock_poke(struct nfsmount *nmp)
{
	struct iovec_32 aio;
	struct msghdr msg;
	size_t len;
	int error = 0;
	int dummy;

	lck_mtx_lock(&nmp->nm_lock);
	if ((nmp->nm_sockflags & NMSOCK_UNMOUNT) || !nmp->nm_so) {
		lck_mtx_unlock(&nmp->nm_lock);
		return;
	}
	lck_mtx_unlock(&nmp->nm_lock);
	aio.iov_base = (uintptr_t)&dummy;
	aio.iov_len = 0;
	len = 0;
	bzero(&msg, sizeof(msg));
	msg.msg_iov = (struct iovec *) &aio;
	msg.msg_iovlen = 1;
	error = sock_send(nmp->nm_so, &msg, MSG_DONTWAIT, &len);
	NFS_SOCK_DBG(("nfs_sock_poke: error %d\n", error));
}

/*
 * Match an RPC reply with the corresponding request
 */
static void
nfs_request_match_reply(struct nfsmount *nmp, mbuf_t mrep)
{
	struct nfsreq *req;
	struct nfsm_chain nmrep;
	u_long reply = 0, rxid = 0;
	long t1;
	int error = 0, asyncioq, asyncgss;

	/* Get the xid and check that it is an rpc reply */
	nfsm_chain_dissect_init(error, &nmrep, mrep);
	nfsm_chain_get_32(error, &nmrep, rxid);
	nfsm_chain_get_32(error, &nmrep, reply);
	if (error || (reply != RPC_REPLY)) {
		OSAddAtomic(1, (SInt32*)&nfsstats.rpcinvalid);
		mbuf_freem(mrep);
		return;
	}

	/*
	 * Loop through the request list to match up the reply
	 * Iff no match, just drop it.
	 */
	lck_mtx_lock(nfs_request_mutex);
	TAILQ_FOREACH(req, &nfs_reqq, r_chain) {
		if (req->r_nmrep.nmc_mhead || (rxid != R_XID32(req->r_xid)))
			continue;
		/* looks like we have it, grab lock and double check */
		lck_mtx_lock(&req->r_mtx);
		if (req->r_nmrep.nmc_mhead || (rxid != R_XID32(req->r_xid))) {
			lck_mtx_unlock(&req->r_mtx);
			continue;
		}
		/* Found it.. */
		req->r_nmrep = nmrep;
		lck_mtx_lock(&nmp->nm_lock);
		if (nmp->nm_sotype == SOCK_DGRAM) {
			/*
			 * Update congestion window.
			 * Do the additive increase of one rpc/rtt.
			 */
			FSDBG(530, R_XID32(req->r_xid), req, nmp->nm_sent, nmp->nm_cwnd);
			if (nmp->nm_cwnd <= nmp->nm_sent) {
				nmp->nm_cwnd +=
				   ((NFS_CWNDSCALE * NFS_CWNDSCALE) +
				    (nmp->nm_cwnd >> 1)) / nmp->nm_cwnd;
				if (nmp->nm_cwnd > NFS_MAXCWND)
					nmp->nm_cwnd = NFS_MAXCWND;
			}
			if (req->r_flags & R_CWND) {
				nmp->nm_sent -= NFS_CWNDSCALE;
				req->r_flags &= ~R_CWND;
			}
			if ((nmp->nm_sent < nmp->nm_cwnd) && !TAILQ_EMPTY(&nmp->nm_cwndq)) {
				/* congestion window is open, poke the cwnd queue */
				struct nfsreq *req2 = TAILQ_FIRST(&nmp->nm_cwndq);
				TAILQ_REMOVE(&nmp->nm_cwndq, req2, r_cchain);
				req2->r_cchain.tqe_next = NFSREQNOLIST;
				wakeup(req2);
			}
		}
		/*
		 * Update rtt using a gain of 0.125 on the mean
		 * and a gain of 0.25 on the deviation.
		 */
		if (req->r_flags & R_TIMING) {
			/*
			 * Since the timer resolution of
			 * NFS_HZ is so course, it can often
			 * result in r_rtt == 0. Since
			 * r_rtt == N means that the actual
			 * rtt is between N+dt and N+2-dt ticks,
			 * add 1.
			 */
			if (proct[req->r_procnum] == 0)
				panic("nfs_request_match_reply: proct[%d] is zero", req->r_procnum);
			t1 = req->r_rtt + 1;
			t1 -= (NFS_SRTT(req) >> 3);
			NFS_SRTT(req) += t1;
			if (t1 < 0)
				t1 = -t1;
			t1 -= (NFS_SDRTT(req) >> 2);
			NFS_SDRTT(req) += t1;
		}
		nmp->nm_timeouts = 0;
		lck_mtx_unlock(&nmp->nm_lock);
		/* signal anyone waiting on this request */
		wakeup(req);
		asyncioq = (req->r_callback.rcb_func != NULL);
		if ((asyncgss = ((req->r_gss_ctx != NULL) && ((req->r_flags & (R_ASYNC|R_ASYNCWAIT|R_ALLOCATED)) == (R_ASYNC|R_ALLOCATED)))))
			nfs_request_ref(req, 1);
		lck_mtx_unlock(&req->r_mtx);
		lck_mtx_unlock(nfs_request_mutex);
		if (asyncgss) {
			nfs_gss_clnt_rpcdone(req);
			nfs_request_rele(req);
		}
		/* if it's an async RPC with a callback, queue it up */
		if (asyncioq)
			nfs_asyncio_finish(req);
		break;
	}

	if (!req) {
		/* not matched to a request, so drop it. */
		lck_mtx_unlock(nfs_request_mutex);
		OSAddAtomic(1, (SInt32*)&nfsstats.rpcunexpected);
		mbuf_freem(mrep);
	}
}

/*
 * Wait for the reply for a given request...
 * ...potentially resending the request if necessary.
 */
static int
nfs_wait_reply(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	struct timespec ts = { 30, 0 };
	int error = 0, slpflag;

	if ((nmp->nm_flag & NFSMNT_INT) && req->r_thread)
		slpflag = PCATCH;
	else
		slpflag = 0;

	lck_mtx_lock(&req->r_mtx);
	while (!req->r_nmrep.nmc_mhead) {
		if ((error = nfs_sigintr(nmp, req, req->r_thread, 0)))
			break;
		if (((error = req->r_error)) || req->r_nmrep.nmc_mhead)
			break;
		/* check if we need to resend */
		if (req->r_flags & R_MUSTRESEND) {
			NFS_SOCK_DBG(("nfs wait resend: p %d x 0x%llx f 0x%x rtt %d\n",
				req->r_procnum, req->r_xid, req->r_flags, req->r_rtt));
			lck_mtx_unlock(&req->r_mtx);
			if (req->r_gss_ctx) {
				/*
				 * It's an RPCSEC_GSS mount.
				 * Can't just resend the original request
				 * without bumping the cred sequence number.
				 * Go back and re-build the request.
				 */
				return (EAGAIN);
			}
			error = nfs_send(req, 1);
			lck_mtx_lock(&req->r_mtx);
			NFS_SOCK_DBG(("nfs wait resend: p %d x 0x%llx f 0x%x rtt %d err %d\n",
				req->r_procnum, req->r_xid, req->r_flags, req->r_rtt, error));
			if (error)
				break;
			if (((error = req->r_error)) || req->r_nmrep.nmc_mhead)
				break;
		}
		/* need to poll if we're P_NOREMOTEHANG */
		if (nfs_noremotehang(req->r_thread))
			ts.tv_sec = 1;
		msleep(req, &req->r_mtx, slpflag | (PZERO - 1), "nfswaitreply", &ts);
		slpflag = 0;
	}
	lck_mtx_unlock(&req->r_mtx);

	return (error);
}

/*
 * An NFS request goes something like this:
 * (nb: always frees up mreq mbuf list)
 * nfs_request_create()
 *	- allocates a request struct if one is not provided
 *	- initial fill-in of the request struct
 * nfs_request_add_header()
 *	- add the RPC header
 * nfs_request_send()
 *	- link it into list
 *	- call nfs_send() for first transmit
 * nfs_request_wait()
 *	- call nfs_wait_reply() to wait for the reply
 * nfs_request_finish()
 *	- break down rpc header and return with error or nfs reply
 *	  pointed to by nmrep.
 * nfs_request_rele()
 * nfs_request_destroy()
 *      - clean up the request struct
 *      - free the request struct if it was allocated by nfs_request_create()
 */

/*
 * Set up an NFS request struct (allocating if no request passed in).
 */
int
nfs_request_create(
	nfsnode_t np,
	mount_t mp,	/* used only if !np */
	struct nfsm_chain *nmrest,
	int procnum,
	thread_t thd,
	kauth_cred_t cred,
	struct nfsreq **reqp)
{
	struct nfsreq *req, *newreq = NULL;
	struct nfsmount *nmp;

	req = *reqp;
	if (!req) {
		/* allocate a new NFS request structure */
		MALLOC_ZONE(newreq, struct nfsreq*, sizeof(*newreq), M_NFSREQ, M_WAITOK);
		if (!newreq) {
			mbuf_freem(nmrest->nmc_mhead);
			nmrest->nmc_mhead = NULL;
			return (ENOMEM);
		}
		req = newreq;
	}

	bzero(req, sizeof(*req));
	if (req == newreq)
		req->r_flags = R_ALLOCATED;

	nmp = VFSTONFS(np ? NFSTOMP(np) : mp);
	if (!nmp) {
		if (newreq)
			FREE_ZONE(newreq, sizeof(*newreq), M_NFSREQ);
		return (ENXIO);
	}
	lck_mtx_lock(&nmp->nm_lock);
	if ((nmp->nm_state & (NFSSTA_FORCE|NFSSTA_TIMEO)) ==
	    (NFSSTA_FORCE|NFSSTA_TIMEO)) {
		lck_mtx_unlock(&nmp->nm_lock);
		mbuf_freem(nmrest->nmc_mhead);
		nmrest->nmc_mhead = NULL;
		if (newreq)
			FREE_ZONE(newreq, sizeof(*newreq), M_NFSREQ);
		return (ENXIO);
	}

	if ((nmp->nm_vers != NFS_VER4) && (procnum >= 0) && (procnum < NFS_NPROCS))
		OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[procnum]);
	if ((nmp->nm_vers == NFS_VER4) && (procnum != NFSPROC4_COMPOUND) && (procnum != NFSPROC4_NULL))
		panic("nfs_request: invalid NFSv4 RPC request %d\n", procnum);

	lck_mtx_init(&req->r_mtx, nfs_request_grp, LCK_ATTR_NULL);
	req->r_nmp = nmp;
	req->r_np = np;
	req->r_thread = thd;
	if (IS_VALID_CRED(cred)) {
		kauth_cred_ref(cred);
		req->r_cred = cred;
	}
	req->r_procnum = procnum;
	if (proct[procnum] > 0)
		req->r_flags |= R_TIMING;
	req->r_nmrep.nmc_mhead = NULL;
	SLIST_INIT(&req->r_gss_seqlist);
	req->r_achain.tqe_next = NFSREQNOLIST;
	req->r_rchain.tqe_next = NFSREQNOLIST;
	req->r_cchain.tqe_next = NFSREQNOLIST;

	lck_mtx_unlock(&nmp->nm_lock);

	/* move the request mbuf chain to the nfsreq */
	req->r_mrest = nmrest->nmc_mhead;
	nmrest->nmc_mhead = NULL;

	req->r_flags |= R_INITTED;
	req->r_refs = 1;
	if (newreq)
		*reqp = req;
	return (0);
}

/*
 * Clean up and free an NFS request structure.
 */
void
nfs_request_destroy(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_np ? NFSTONMP(req->r_np) : req->r_nmp;
	struct gss_seq *gsp, *ngsp;
	struct timespec ts = { 1, 0 };

	if (!req || !(req->r_flags & R_INITTED))
		return;
	req->r_flags &= ~R_INITTED;
	if (req->r_lflags & RL_QUEUED)
		nfs_reqdequeue(req);
	if (req->r_achain.tqe_next != NFSREQNOLIST) {
		/* still on an async I/O queue? */
		lck_mtx_lock(nfsiod_mutex);
		if (nmp && (req->r_achain.tqe_next != NFSREQNOLIST)) {
			TAILQ_REMOVE(&nmp->nm_iodq, req, r_achain);
			req->r_achain.tqe_next = NFSREQNOLIST;
		}
		lck_mtx_unlock(nfsiod_mutex);
	}
	if (nmp) {
		lck_mtx_lock(&nmp->nm_lock);
		if (req->r_rchain.tqe_next != NFSREQNOLIST) {
			TAILQ_REMOVE(&nmp->nm_resendq, req, r_rchain);
			req->r_rchain.tqe_next = NFSREQNOLIST;
			req->r_flags &= ~R_RESENDQ;
		}
		if (req->r_cchain.tqe_next != NFSREQNOLIST) {
			TAILQ_REMOVE(&nmp->nm_cwndq, req, r_cchain);
			req->r_cchain.tqe_next = NFSREQNOLIST;
		}
		lck_mtx_unlock(&nmp->nm_lock);
	}
	lck_mtx_lock(&req->r_mtx);
	while (req->r_flags & R_RESENDQ)
		msleep(req, &req->r_mtx, (PZERO - 1), "nfsresendqwait", &ts);
	lck_mtx_unlock(&req->r_mtx);
	if (req->r_mhead)
		mbuf_freem(req->r_mhead);
	else if (req->r_mrest)
		mbuf_freem(req->r_mrest);
	if (req->r_nmrep.nmc_mhead)
		mbuf_freem(req->r_nmrep.nmc_mhead);
	if (IS_VALID_CRED(req->r_cred))
		kauth_cred_unref(&req->r_cred);
	if (req->r_gss_ctx)
		nfs_gss_clnt_rpcdone(req);
	SLIST_FOREACH_SAFE(gsp, &req->r_gss_seqlist, gss_seqnext, ngsp)
		FREE(gsp, M_TEMP);
	if (req->r_gss_ctx)
		nfs_gss_clnt_ctx_unref(req);

	lck_mtx_destroy(&req->r_mtx, nfs_request_grp);
	if (req->r_flags & R_ALLOCATED)
		FREE_ZONE(req, sizeof(*req), M_NFSREQ);
}

void
nfs_request_ref(struct nfsreq *req, int locked)
{
	if (!locked)
		lck_mtx_lock(&req->r_mtx);
	if (req->r_refs <= 0)
		panic("nfsreq reference error");
	req->r_refs++;
	if (!locked)
		lck_mtx_unlock(&req->r_mtx);
}

void
nfs_request_rele(struct nfsreq *req)
{
	int destroy;

	lck_mtx_lock(&req->r_mtx);
	if (req->r_refs <= 0)
		panic("nfsreq reference underflow");
	req->r_refs--;
	destroy = (req->r_refs == 0);
	lck_mtx_unlock(&req->r_mtx);
	if (destroy)
		nfs_request_destroy(req);
}


/*
 * Add an (updated) RPC header with authorization to an NFS request.
 */
int
nfs_request_add_header(struct nfsreq *req)
{
	struct nfsmount *nmp;
	int error = 0, auth_len = 0;
	mbuf_t m;

	/* free up any previous header */
	if ((m = req->r_mhead)) {
		while (m && (m != req->r_mrest))
			m = mbuf_free(m);
		req->r_mhead = NULL;
	}

	nmp = req->r_np ? NFSTONMP(req->r_np) : req->r_nmp;
	if (!nmp)
		return (ENXIO);

	if (!req->r_cred) /* RPCAUTH_NULL */
		auth_len = 0;
	else switch (nmp->nm_auth) {
		case RPCAUTH_UNIX:
			if (req->r_cred->cr_ngroups < 1)
				return (EINVAL);
			auth_len = ((((req->r_cred->cr_ngroups - 1) > nmp->nm_numgrps) ?
				nmp->nm_numgrps : (req->r_cred->cr_ngroups - 1)) << 2) +
				5 * NFSX_UNSIGNED;
			break;
		case RPCAUTH_KRB5:
		case RPCAUTH_KRB5I:
		case RPCAUTH_KRB5P:
			auth_len = 5 * NFSX_UNSIGNED + 0; // zero context handle for now
			break;
		}

	error = nfsm_rpchead(req, auth_len, req->r_mrest, &req->r_xid, &req->r_mhead);
	if (error)
		return (error);

	req->r_mreqlen = mbuf_pkthdr_len(req->r_mhead);
	nmp = req->r_np ? NFSTONMP(req->r_np) : req->r_nmp;
	if (!nmp)
		return (ENXIO);
	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_flag & NFSMNT_SOFT)
		req->r_retry = nmp->nm_retry;
	else
		req->r_retry = NFS_MAXREXMIT + 1;	/* past clip limit */
	lck_mtx_unlock(&nmp->nm_lock);

	return (error);
}


/*
 * Queue an NFS request up and send it out.
 */
int
nfs_request_send(struct nfsreq *req, int wait)
{
	struct nfsmount *nmp;
	struct timeval now;

	lck_mtx_lock(nfs_request_mutex);

	nmp = req->r_np ? NFSTONMP(req->r_np) : req->r_nmp;
	if (!nmp) {
		lck_mtx_unlock(nfs_request_mutex);
		return (ENXIO);
	}

	microuptime(&now);
	if (!req->r_start) {
		req->r_start = now.tv_sec;
		req->r_lastmsg = now.tv_sec -
		    ((nmp->nm_tprintf_delay) - (nmp->nm_tprintf_initial_delay));
	}

	OSAddAtomic(1, (SInt32*)&nfsstats.rpcrequests);

	/*
	 * Chain request into list of outstanding requests. Be sure
	 * to put it LAST so timer finds oldest requests first.
	 * Make sure that the request queue timer is running
	 * to check for possible request timeout.
	 */
	TAILQ_INSERT_TAIL(&nfs_reqq, req, r_chain);
	req->r_lflags |= RL_QUEUED;
	if (!nfs_request_timer_on) {
		nfs_request_timer_on = 1;
		nfs_interval_timer_start(nfs_request_timer_call,
			NFS_REQUESTDELAY);
	}
	lck_mtx_unlock(nfs_request_mutex);

	/* Send the request... */
	return (nfs_send(req, wait));
}

/*
 * Call nfs_wait_reply() to wait for the reply.
 */
void
nfs_request_wait(struct nfsreq *req)
{
	req->r_error = nfs_wait_reply(req);
}

/*
 * Finish up an NFS request by dequeueing it and
 * doing the initial NFS request reply processing.
 */
int
nfs_request_finish(
	struct nfsreq *req,
	struct nfsm_chain *nmrepp,
	int *status)
{
	struct nfsmount *nmp;
	mbuf_t mrep;
	int verf_type = 0;
	uint32_t verf_len = 0;
	uint32_t reply_status = 0;
	uint32_t rejected_status = 0;
	uint32_t auth_status = 0;
	uint32_t accepted_status = 0;
	struct nfsm_chain nmrep;
	int error, auth;

	error = req->r_error;

	if (nmrepp)
		nmrepp->nmc_mhead = NULL;

	/* RPC done, unlink the request. */
	nfs_reqdequeue(req);

	mrep = req->r_nmrep.nmc_mhead;

	nmp = req->r_np ? NFSTONMP(req->r_np) : req->r_nmp;

	/*
	 * Decrement the outstanding request count.
	 */
	if (req->r_flags & R_CWND) {
		req->r_flags &= ~R_CWND;
		lck_mtx_lock(&nmp->nm_lock);
		FSDBG(273, R_XID32(req->r_xid), req, nmp->nm_sent, nmp->nm_cwnd);
		nmp->nm_sent -= NFS_CWNDSCALE;
		if ((nmp->nm_sent < nmp->nm_cwnd) && !TAILQ_EMPTY(&nmp->nm_cwndq)) {
			/* congestion window is open, poke the cwnd queue */
			struct nfsreq *req2 = TAILQ_FIRST(&nmp->nm_cwndq);
			TAILQ_REMOVE(&nmp->nm_cwndq, req2, r_cchain);
			req2->r_cchain.tqe_next = NFSREQNOLIST;
			wakeup(req2);
		}
		lck_mtx_unlock(&nmp->nm_lock);
	}

	if (req->r_gss_ctx) {	// Using gss cred ?
		/*
		 * If the request had an RPCSEC_GSS credential
		 * then reset its sequence number bit in the
		 * request window.
		 */
		nfs_gss_clnt_rpcdone(req);

		/*
		 * If we need to re-send, go back and re-build the
		 * request based on a new sequence number.
		 * Note that we're using the original XID.
		 */
		if (error == EAGAIN) {
			req->r_error = 0;
			if (mrep)
				mbuf_freem(mrep);
			error = nfs_gss_clnt_args_restore(req);	// remove any trailer mbufs
			req->r_nmrep.nmc_mhead = NULL;
			req->r_flags |= R_RESTART;
			if (error == ENEEDAUTH) {
				req->r_xid = 0;		// get a new XID
				error = 0;
			}
			goto nfsmout;
		}
	}

	/*
	 * If there was a successful reply, make sure to mark the mount as up.
	 * If a tprintf message was given (or if this is a timed-out soft mount)
	 * then post a tprintf message indicating the server is alive again.
	 */
	if (!error) {
		if ((req->r_flags & R_TPRINTFMSG) ||
		    (nmp && (nmp->nm_flag & NFSMNT_SOFT) &&
		     ((nmp->nm_state & (NFSSTA_TIMEO|NFSSTA_FORCE)) == NFSSTA_TIMEO)))
			nfs_up(nmp, req->r_thread, NFSSTA_TIMEO, "is alive again");
		else
			nfs_up(nmp, req->r_thread, NFSSTA_TIMEO, NULL);
	}
	if (!error && !nmp)
		error = ENXIO;
	nfsmout_if(error);

	/*
	 * break down the RPC header and check if ok
	 */
	nmrep = req->r_nmrep;
	nfsm_chain_get_32(error, &nmrep, reply_status);
	nfsmout_if(error);
	if (reply_status == RPC_MSGDENIED) {
		nfsm_chain_get_32(error, &nmrep, rejected_status);
		nfsmout_if(error);
		if (rejected_status == RPC_MISMATCH) {
			error = ENOTSUP;
			goto nfsmout;
		}
		nfsm_chain_get_32(error, &nmrep, auth_status);
		nfsmout_if(error);
		switch (auth_status) {
		case RPCSEC_GSS_CREDPROBLEM:
		case RPCSEC_GSS_CTXPROBLEM:
			/*
			 * An RPCSEC_GSS cred or context problem.
			 * We can't use it anymore.
			 * Restore the args, renew the context
			 * and set up for a resend.
			 */
			error = nfs_gss_clnt_args_restore(req);
			if (error && error != ENEEDAUTH)
				break;
			
			if (!error) {
				error = nfs_gss_clnt_ctx_renew(req);
				if (error)
					break;
			}
			mbuf_freem(mrep);
			req->r_nmrep.nmc_mhead = NULL;
			req->r_xid = 0;		// get a new XID
			req->r_flags |= R_RESTART;
			goto nfsmout;
		default:
			error = EACCES;
			break;
		}
		goto nfsmout;
	}

	/* Now check the verifier */
	nfsm_chain_get_32(error, &nmrep, verf_type); // verifier flavor
	nfsm_chain_get_32(error, &nmrep, verf_len);  // verifier length
	nfsmout_if(error);

	auth = !req->r_cred ? RPCAUTH_NULL : nmp->nm_auth;
	switch (auth) {
	case RPCAUTH_NULL:
	case RPCAUTH_UNIX:
		/* Any AUTH_UNIX verifier is ignored */
		if (verf_len > 0)
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(verf_len));
		nfsm_chain_get_32(error, &nmrep, accepted_status);
		break;
	case RPCAUTH_KRB5:
	case RPCAUTH_KRB5I:
	case RPCAUTH_KRB5P:
		error = nfs_gss_clnt_verf_get(req, &nmrep,
			verf_type, verf_len, &accepted_status);
		break;
	}
	nfsmout_if(error);

	switch (accepted_status) {
	case RPC_SUCCESS:
		if (req->r_procnum == NFSPROC_NULL) {
			/*
			 * The NFS null procedure is unique,
			 * in not returning an NFS status.
			 */
			*status = NFS_OK;
		} else {
			nfsm_chain_get_32(error, &nmrep, *status);
			nfsmout_if(error);
		}

		if ((nmp->nm_vers != NFS_VER2) && (*status == NFSERR_TRYLATER)) {
			/*
			 * It's a JUKEBOX error - delay and try again
			 */
			int delay, slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

			mbuf_freem(mrep);
			req->r_nmrep.nmc_mhead = NULL;
			if ((req->r_delay >= 30) && !(nmp->nm_state & NFSSTA_MOUNTED)) {
				/* we're not yet completely mounted and */
				/* we can't complete an RPC, so we fail */
				OSAddAtomic(1, (SInt32*)&nfsstats.rpctimeouts);
				nfs_softterm(req);
				error = req->r_error;
				goto nfsmout;
			}
			req->r_delay = !req->r_delay ? NFS_TRYLATERDEL : (req->r_delay * 2);
			if (req->r_delay > 30)
				req->r_delay = 30;
			if (nmp->nm_tprintf_initial_delay && (req->r_delay == 30)) {
				nfs_down(req->r_nmp, req->r_thread, 0, NFSSTA_JUKEBOXTIMEO,
					"resource temporarily unavailable (jukebox)");
				req->r_flags |= R_JBTPRINTFMSG;
			}
			delay = req->r_delay;
			if (req->r_callback.rcb_func) {
				struct timeval now;
				microuptime(&now);
				req->r_resendtime = now.tv_sec + delay;
			} else {
				do {
					if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 0)))
						return (error);
					tsleep(&lbolt, PSOCK|slpflag, "nfs_jukebox_trylater", 0);
				} while (--delay > 0);
			}
			req->r_xid = 0;			// get a new XID
			req->r_flags |= R_RESTART;
			req->r_start = 0;
			FSDBG(273, R_XID32(req->r_xid), nmp, req, NFSERR_TRYLATER);
			return (0);
		}

		if (req->r_flags & R_JBTPRINTFMSG)
			nfs_up(nmp, req->r_thread, NFSSTA_JUKEBOXTIMEO, "resource available again");

		if (*status == NFS_OK) {
			/*
			 * Successful NFS request
			 */
			*nmrepp = nmrep;
			req->r_nmrep.nmc_mhead = NULL;
			break;
		}
		/* Got an NFS error of some kind */

		/*
		 * If the File Handle was stale, invalidate the
		 * lookup cache, just in case.
		 */
		if ((*status == ESTALE) && req->r_np)
			cache_purge(NFSTOV(req->r_np));
		if (nmp->nm_vers == NFS_VER2)
			mbuf_freem(mrep);
		else
			*nmrepp = nmrep;
		req->r_nmrep.nmc_mhead = NULL;
		error = 0;
		break;
	case RPC_PROGUNAVAIL:
		error = EPROGUNAVAIL;
		break;
	case RPC_PROGMISMATCH:
		error = ERPCMISMATCH;
		break;
	case RPC_PROCUNAVAIL:
		error = EPROCUNAVAIL;
		break;
	case RPC_GARBAGE:
		error = EBADRPC;
		break;
	case RPC_SYSTEM_ERR:
	default:
		error = EIO;
		break;
	}
nfsmout:
	if (!error && (req->r_flags & R_JBTPRINTFMSG))
		nfs_up(nmp, req->r_thread, NFSSTA_JUKEBOXTIMEO, NULL);
	FSDBG(273, R_XID32(req->r_xid), nmp, req,
		(!error && (*status == NFS_OK)) ? 0xf0f0f0f0 : error);
	return (error);
}


/*
 * Perform an NFS request synchronously.
 */

int
nfs_request(
	nfsnode_t np,
	mount_t mp,	/* used only if !np */
	struct nfsm_chain *nmrest,
	int procnum,
	vfs_context_t ctx,
	struct nfsm_chain *nmrepp,
	u_int64_t *xidp,
	int *status)
{
	return nfs_request2(np, mp, nmrest, procnum,
		vfs_context_thread(ctx), vfs_context_ucred(ctx),
		0, nmrepp, xidp, status);
}

int
nfs_request2(
	nfsnode_t np,
	mount_t mp,	/* used only if !np */
	struct nfsm_chain *nmrest,
	int procnum,
	thread_t thd,
	kauth_cred_t cred,
	int flags,
	struct nfsm_chain *nmrepp,
	u_int64_t *xidp,
	int *status)
{
	struct nfsreq rq, *req = &rq;
	int error;

	if ((error = nfs_request_create(np, mp, nmrest, procnum, thd, cred, &req)))
		return (error);
	req->r_flags |= (flags & R_OPTMASK);

	FSDBG_TOP(273, R_XID32(req->r_xid), np, procnum, 0);
	do {
		req->r_error = 0;
		req->r_flags &= ~R_RESTART;
		if ((error = nfs_request_add_header(req)))
			break;
		if (xidp)
			*xidp = req->r_xid;
		if ((error = nfs_request_send(req, 1)))
			break;
		nfs_request_wait(req);
		if ((error = nfs_request_finish(req, nmrepp, status)))
			break;
	} while (req->r_flags & R_RESTART);

	FSDBG_BOT(273, R_XID32(req->r_xid), np, procnum, error);
	nfs_request_rele(req);
	return (error);
}

/*
 * Create and start an asynchronous NFS request.
 */
int
nfs_request_async(
	nfsnode_t np,
	mount_t mp,	/* used only if !np */
	struct nfsm_chain *nmrest,
	int procnum,
	thread_t thd,
	kauth_cred_t cred,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsreq *req;
	int error, sent;

	error = nfs_request_create(np, mp, nmrest, procnum, thd, cred, reqp);
	req = *reqp;
	FSDBG(274, (req ? R_XID32(req->r_xid) : 0), np, procnum, error);
	if (error)
		return (error);
	req->r_flags |= R_ASYNC;
	if (cb)
		req->r_callback = *cb;
	error = nfs_request_add_header(req);
	if (!error) {
		req->r_flags |= R_WAITSENT;
		if (req->r_callback.rcb_func)
			nfs_request_ref(req, 0);
		error = nfs_request_send(req, 1);
		lck_mtx_lock(&req->r_mtx);
		if (!error && !(req->r_flags & R_SENT) && req->r_callback.rcb_func) {
			/* make sure to wait until this async I/O request gets sent */
			int slpflag = (req->r_nmp && (req->r_nmp->nm_flag & NFSMNT_INT) && req->r_thread) ? PCATCH : 0;
			struct timespec ts = { 2, 0 };
			while (!(req->r_flags & R_SENT)) {
				if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 0)))
					break;
				msleep(req, &req->r_mtx, slpflag | (PZERO - 1), "nfswaitsent", &ts);
				slpflag = 0;
			}
		}
		sent = req->r_flags & R_SENT;
		lck_mtx_unlock(&req->r_mtx);
		if (error && req->r_callback.rcb_func && !sent)
			nfs_request_rele(req);
	}
	FSDBG(274, R_XID32(req->r_xid), np, procnum, error);
	if (error || req->r_callback.rcb_func)
		nfs_request_rele(req);
	return (error);
}

/*
 * Wait for and finish an asynchronous NFS request.
 */
int
nfs_request_async_finish(
	struct nfsreq *req,
	struct nfsm_chain *nmrepp,
	u_int64_t *xidp,
	int *status)
{
	int error, asyncio = req->r_callback.rcb_func ? 1 : 0;

	lck_mtx_lock(&req->r_mtx);
	if (!asyncio)
		req->r_flags |= R_ASYNCWAIT;
	while (req->r_flags & R_RESENDQ) /* wait until the request is off the resend queue */
		msleep(req, &req->r_mtx, PZERO-1, "nfsresendqwait", NULL);
	lck_mtx_unlock(&req->r_mtx);

	nfs_request_wait(req);
	error = nfs_request_finish(req, nmrepp, status);

	while (!error && (req->r_flags & R_RESTART)) {
		if (asyncio && req->r_resendtime) {  /* send later */
			lck_mtx_lock(&req->r_mtx);
			nfs_asyncio_resend(req);
			lck_mtx_unlock(&req->r_mtx);
			return (EINPROGRESS);
		}
		req->r_error = 0;
		req->r_flags &= ~R_RESTART;
		if ((error = nfs_request_add_header(req)))
			break;
		if ((error = nfs_request_send(req, !asyncio)))
			break;
		if (asyncio)
			return (EINPROGRESS);
		nfs_request_wait(req);
		if ((error = nfs_request_finish(req, nmrepp, status)))
			break;
	}
	if (xidp)
		*xidp = req->r_xid;

	FSDBG(275, R_XID32(req->r_xid), req->r_np, req->r_procnum, error);
	nfs_request_rele(req);
	return (error);
}

/*
 * Cancel a pending asynchronous NFS request.
 */
void
nfs_request_async_cancel(struct nfsreq *req)
{
	nfs_reqdequeue(req);
	FSDBG(275, R_XID32(req->r_xid), req->r_np, req->r_procnum, 0xD1ED1E);
	nfs_request_rele(req);
}

/*
 * Flag a request as being terminated.
 */
static void
nfs_softterm(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	req->r_flags |= R_SOFTTERM;
	req->r_error = ETIMEDOUT;
	if (!(req->r_flags & R_CWND) || !nmp)
		return;
	/* update congestion window */
	req->r_flags &= ~R_CWND;
	lck_mtx_lock(&nmp->nm_lock);
	FSDBG(532, R_XID32(req->r_xid), req, nmp->nm_sent, nmp->nm_cwnd);
	nmp->nm_sent -= NFS_CWNDSCALE;
	if ((nmp->nm_sent < nmp->nm_cwnd) && !TAILQ_EMPTY(&nmp->nm_cwndq)) {
		/* congestion window is open, poke the cwnd queue */
		struct nfsreq *req2 = TAILQ_FIRST(&nmp->nm_cwndq);
		TAILQ_REMOVE(&nmp->nm_cwndq, req2, r_cchain);
		req2->r_cchain.tqe_next = NFSREQNOLIST;
		wakeup(req2);
	}
	lck_mtx_unlock(&nmp->nm_lock);
}

/*
 * Ensure req isn't in use by the timer, then dequeue it.
 */
static void
nfs_reqdequeue(struct nfsreq *req)
{
	lck_mtx_lock(nfs_request_mutex);
	while (req->r_lflags & RL_BUSY) {
		req->r_lflags |= RL_WAITING;
		msleep(&req->r_lflags, nfs_request_mutex, PSOCK, "reqdeq", NULL);
	}
	if (req->r_lflags & RL_QUEUED) {
		TAILQ_REMOVE(&nfs_reqq, req, r_chain);
		req->r_lflags &= ~RL_QUEUED;
	}
	lck_mtx_unlock(nfs_request_mutex);
}

/*
 * Busy (lock) a nfsreq, used by the nfs timer to make sure it's not
 * free()'d out from under it.
 */
static void
nfs_reqbusy(struct nfsreq *req)
{
	if (req->r_lflags & RL_BUSY)
		panic("req locked");
	req->r_lflags |= RL_BUSY;
}

/*
 * Unbusy the nfsreq passed in, return the next nfsreq in the chain busied.
 */
static struct nfsreq *
nfs_reqnext(struct nfsreq *req)
{
	struct nfsreq * nextreq;

	if (req == NULL)
		return (NULL);
	/*
	 * We need to get and busy the next req before signalling the
	 * current one, otherwise wakeup() may block us and we'll race to
	 * grab the next req.
	 */
	nextreq = TAILQ_NEXT(req, r_chain);
	if (nextreq != NULL)
		nfs_reqbusy(nextreq);
	/* unbusy and signal. */
	req->r_lflags &= ~RL_BUSY;
	if (req->r_lflags & RL_WAITING) {
		req->r_lflags &= ~RL_WAITING;
		wakeup(&req->r_lflags);
	}
	return (nextreq);
}

/*
 * NFS request queue timer routine
 *
 * Scan the NFS request queue for any requests that have timed out.
 *
 * Alert the system of unresponsive servers.
 * Mark expired requests on soft mounts as terminated.
 * For UDP, mark/signal requests for retransmission.
 */
void
nfs_request_timer(__unused void *param0, __unused void *param1)
{
	struct nfsreq *req;
	struct nfsmount *nmp;
	int timeo, maxtime, finish_asyncio, error;
	struct timeval now;
	TAILQ_HEAD(nfs_mount_pokeq, nfsmount) nfs_mount_poke_queue;

	lck_mtx_lock(nfs_request_mutex);
	req = TAILQ_FIRST(&nfs_reqq);
	if (req == NULL) {	/* no requests - turn timer off */
		nfs_request_timer_on = 0;
		lck_mtx_unlock(nfs_request_mutex);
		return;
	}

	nfs_reqbusy(req);
	TAILQ_INIT(&nfs_mount_poke_queue);

	microuptime(&now);
	for ( ; req != NULL ; req = nfs_reqnext(req)) {
		nmp = req->r_nmp;
		if (!nmp) /* unmounted */
			continue;
		if (req->r_error || req->r_nmrep.nmc_mhead)
			continue;
		if ((error = nfs_sigintr(nmp, req, req->r_thread, 0))) {
			if (req->r_callback.rcb_func != NULL) {
				/* async I/O RPC needs to be finished */
				lck_mtx_lock(&req->r_mtx);
				req->r_error = error;
				finish_asyncio = !(req->r_flags & R_WAITSENT);
				wakeup(req);
				lck_mtx_unlock(&req->r_mtx);
				if (finish_asyncio)
					nfs_asyncio_finish(req);
			}
			continue;
		}

		lck_mtx_lock(&req->r_mtx);

		if (nmp->nm_tprintf_initial_delay &&
		    ((req->r_rexmit > 2) || (req->r_flags & R_RESENDERR)) &&
		    ((req->r_lastmsg + nmp->nm_tprintf_delay) < now.tv_sec)) {
			req->r_lastmsg = now.tv_sec;
			nfs_down(req->r_nmp, req->r_thread, 0, NFSSTA_TIMEO,
				"not responding");
			req->r_flags |= R_TPRINTFMSG;
			lck_mtx_lock(&nmp->nm_lock);
			if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
				lck_mtx_unlock(&nmp->nm_lock);
				/* we're not yet completely mounted and */
				/* we can't complete an RPC, so we fail */
				OSAddAtomic(1, (SInt32*)&nfsstats.rpctimeouts);
				nfs_softterm(req);
				finish_asyncio = ((req->r_callback.rcb_func != NULL) && !(req->r_flags & R_WAITSENT));
				wakeup(req);
				lck_mtx_unlock(&req->r_mtx);
				if (finish_asyncio)
					nfs_asyncio_finish(req);
				continue;
			}
			lck_mtx_unlock(&nmp->nm_lock);
		}

		/*
		 * Put a reasonable limit on the maximum timeout,
		 * and reduce that limit when soft mounts get timeouts or are in reconnect.
		 */
		if (!(nmp->nm_flag & NFSMNT_SOFT))
			maxtime = NFS_MAXTIMEO;
		else if ((req->r_flags & R_SETUP) || ((nmp->nm_reconnect_start <= 0) || ((now.tv_sec - nmp->nm_reconnect_start) < 8)))
			maxtime = (NFS_MAXTIMEO / (nmp->nm_timeouts+1))/2;
		else
			maxtime = NFS_MINTIMEO/4;

		/*
		 * Check for request timeout.
		 */
		if (req->r_rtt >= 0) {
			req->r_rtt++;
			lck_mtx_lock(&nmp->nm_lock);
			if (req->r_flags & R_RESENDERR) {
				/* with resend errors, retry every few seconds */
				timeo = 4*hz;
			} else {
				if (req->r_procnum == NFSPROC_NULL && req->r_gss_ctx != NULL)
					timeo = NFS_MINIDEMTIMEO; // gss context setup
				else if (nmp->nm_flag & NFSMNT_DUMBTIMR)
					timeo = nmp->nm_timeo;
				else
					timeo = NFS_RTO(nmp, proct[req->r_procnum]);

				/* ensure 62.5 ms floor */
				while (16 * timeo < hz)
					timeo *= 2;
				if (nmp->nm_timeouts > 0)
					timeo *= nfs_backoff[nmp->nm_timeouts - 1];
			}
			/* limit timeout to max */
			if (timeo > maxtime)
				timeo = maxtime;
			if (req->r_rtt <= timeo) {
				lck_mtx_unlock(&nmp->nm_lock);
				lck_mtx_unlock(&req->r_mtx);
				continue;
			}
			/* The request has timed out */
			NFS_SOCK_DBG(("nfs timeout: proc %d %d xid %llx rtt %d to %d # %d, t %ld/%d\n",
				req->r_procnum, proct[req->r_procnum],
				req->r_xid, req->r_rtt, timeo, nmp->nm_timeouts,
				(now.tv_sec - req->r_start)*NFS_HZ, maxtime));
			if (nmp->nm_timeouts < 8)
				nmp->nm_timeouts++;
			/* if it's been a few seconds, try poking the socket */
			if ((nmp->nm_sotype == SOCK_STREAM) &&
			    ((now.tv_sec - req->r_start) >= 3) &&
			    !(nmp->nm_sockflags & NMSOCK_POKE)) {
				nmp->nm_sockflags |= NMSOCK_POKE;
				TAILQ_INSERT_TAIL(&nfs_mount_poke_queue, nmp, nm_pokeq);
			}
			lck_mtx_unlock(&nmp->nm_lock);
		}

		/* For soft mounts (& SETUPs), check for too many retransmits/timeout. */
		if (((nmp->nm_flag & NFSMNT_SOFT) || (req->r_flags & R_SETUP)) &&
		    ((req->r_rexmit >= req->r_retry) || /* too many */
		     ((now.tv_sec - req->r_start)*NFS_HZ > maxtime))) { /* too long */
			OSAddAtomic(1, (SInt32*)&nfsstats.rpctimeouts);
			lck_mtx_lock(&nmp->nm_lock);
			if (!(nmp->nm_state & NFSSTA_TIMEO)) {
				lck_mtx_unlock(&nmp->nm_lock);
				/* make sure we note the unresponsive server */
				/* (maxtime may be less than tprintf delay) */
				nfs_down(req->r_nmp, req->r_thread, 0, NFSSTA_TIMEO,
					"not responding");
				req->r_lastmsg = now.tv_sec;
				req->r_flags |= R_TPRINTFMSG;
			} else {
				lck_mtx_unlock(&nmp->nm_lock);
			}
			NFS_SOCK_DBG(("nfs timer TERMINATE: p %d x 0x%llx f 0x%x rtt %d t %ld\n",
				req->r_procnum, req->r_xid, req->r_flags, req->r_rtt,
				now.tv_sec - req->r_start));
			nfs_softterm(req);
			finish_asyncio = ((req->r_callback.rcb_func != NULL) && !(req->r_flags & R_WAITSENT));
			wakeup(req);
			lck_mtx_unlock(&req->r_mtx);
			if (finish_asyncio)
				nfs_asyncio_finish(req);
			continue;
		}

		/* for TCP, only resend if explicitly requested */
		if ((nmp->nm_sotype == SOCK_STREAM) && !(req->r_flags & R_MUSTRESEND)) {
			if (++req->r_rexmit > NFS_MAXREXMIT)
				req->r_rexmit = NFS_MAXREXMIT;
			req->r_rtt = 0;
			lck_mtx_unlock(&req->r_mtx);
			continue;
		}

		/*
		 * The request needs to be (re)sent.  Kick the requester to resend it.
		 * (unless it's already marked as needing a resend)
		 */
		if ((req->r_flags & R_MUSTRESEND) && (req->r_rtt == -1)) {
			lck_mtx_unlock(&req->r_mtx);
			continue;
		}
		NFS_SOCK_DBG(("nfs timer mark resend: p %d x 0x%llx f 0x%x rtt %d\n",
			req->r_procnum, req->r_xid, req->r_flags, req->r_rtt));
		req->r_flags |= R_MUSTRESEND;
		req->r_rtt = -1;
		wakeup(req);
		if ((req->r_flags & (R_ASYNC|R_ASYNCWAIT)) == R_ASYNC)
			nfs_asyncio_resend(req);
		lck_mtx_unlock(&req->r_mtx);
	}

	lck_mtx_unlock(nfs_request_mutex);

	/* poke any sockets */
	while ((nmp = TAILQ_FIRST(&nfs_mount_poke_queue))) {
		TAILQ_REMOVE(&nfs_mount_poke_queue, nmp, nm_pokeq);
		nfs_sock_poke(nmp);
		lck_mtx_lock(&nmp->nm_lock);
		nmp->nm_sockflags &= ~NMSOCK_POKE;
		if (!(nmp->nm_state & NFSSTA_MOUNTED))
			wakeup(&nmp->nm_sockflags);
		lck_mtx_unlock(&nmp->nm_lock);
	}

	nfs_interval_timer_start(nfs_request_timer_call, NFS_REQUESTDELAY);
}

/*
 * check a thread's proc for the "noremotehang" flag.
 */
int
nfs_noremotehang(thread_t thd)
{
	proc_t p = thd ? get_bsdthreadtask_info(thd) : NULL;
	return (p && proc_noremotehang(p));
}

/*
 * Test for a termination condition pending on the process.
 * This is used to determine if we need to bail on a mount.
 * ETIMEDOUT is returned if there has been a soft timeout.
 * EINTR is returned if there is a signal pending that is not being ignored
 * and the mount is interruptable, or if we are a thread that is in the process
 * of cancellation (also SIGKILL posted).
 */
int
nfs_sigintr(struct nfsmount *nmp, struct nfsreq *req, thread_t thd, int nmplocked)
{
	int error = 0;

	if (nmp == NULL)
		return (ENXIO);

	if (req && (req->r_flags & R_SOFTTERM))
		return (ETIMEDOUT); /* request has been terminated. */

	/*
	 * If we're in the progress of a force unmount and there's
	 * been a timeout, we're dead and fail IO.
	 */
	if (!nmplocked)
		lck_mtx_lock(&nmp->nm_lock);
	if ((nmp->nm_state & NFSSTA_FORCE) &&
	    (nmp->nm_state & (NFSSTA_TIMEO|NFSSTA_JUKEBOXTIMEO|NFSSTA_LOCKTIMEO))) {
		error = EIO;
	} else if (nmp->nm_mountp->mnt_kern_flag & MNTK_FRCUNMOUNT) {
		/* Someone is unmounting us, go soft and mark it. */
		nmp->nm_flag |= NFSMNT_SOFT;
		nmp->nm_state |= NFSSTA_FORCE;
	}

	/*
	 * If the mount is hung and we've requested not to hang
	 * on remote filesystems, then bail now.
	 */
	if (!error && (nmp->nm_state & NFSSTA_TIMEO) && nfs_noremotehang(thd))
		error = EIO;

	if (!nmplocked)
		lck_mtx_unlock(&nmp->nm_lock);
	if (error)
		return (error);

	/* may not have a thread for async I/O */
	if (thd == NULL)
		return (0);

	/* If this thread belongs to kernel task; then abort check is not needed */
	if ((current_proc() != kernproc) && current_thread_aborted())
		return (EINTR);

	/* mask off thread and process blocked signals. */
	if ((nmp->nm_flag & NFSMNT_INT) &&
	    proc_pendingsignals(get_bsdthreadtask_info(thd), NFSINT_SIGMASK))
		return (EINTR);
	return (0);
}

/*
 * Lock a socket against others.
 * Necessary for STREAM sockets to ensure you get an entire rpc request/reply
 * and also to avoid race conditions between the processes with nfs requests
 * in progress when a reconnect is necessary.
 */
int
nfs_sndlock(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	int *statep;
	int error = 0, slpflag = 0;
	struct timespec ts = { 0, 0 };

	if (nmp == NULL)
		return (ENXIO);

	lck_mtx_lock(&nmp->nm_lock);
	statep = &nmp->nm_state;

	if ((nmp->nm_flag & NFSMNT_INT) && req->r_thread)
		slpflag = PCATCH;
	while (*statep & NFSSTA_SNDLOCK) {
		if ((error = nfs_sigintr(nmp, req, req->r_thread, 1)))
			break;
		*statep |= NFSSTA_WANTSND;
		if (nfs_noremotehang(req->r_thread))
			ts.tv_sec = 1;
		msleep(statep, &nmp->nm_lock, slpflag | (PZERO - 1), "nfsndlck", &ts);
		if (slpflag == PCATCH) {
			slpflag = 0;
			ts.tv_sec = 2;
		}
	}
	if (!error)
		*statep |= NFSSTA_SNDLOCK;
	lck_mtx_unlock(&nmp->nm_lock);
	return (error);
}

/*
 * Unlock the stream socket for others.
 */
void
nfs_sndunlock(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	int *statep, wake = 0;

	if (nmp == NULL)
		return;
	lck_mtx_lock(&nmp->nm_lock);
	statep = &nmp->nm_state;
	if ((*statep & NFSSTA_SNDLOCK) == 0)
		panic("nfs sndunlock");
	*statep &= ~NFSSTA_SNDLOCK;
	if (*statep & NFSSTA_WANTSND) {
		*statep &= ~NFSSTA_WANTSND;
		wake = 1;
	}
	lck_mtx_unlock(&nmp->nm_lock);
	if (wake)
		wakeup(statep);
}

#endif /* NFSCLIENT */

#if NFSSERVER

/*
 * Generate the rpc reply header
 * siz arg. is used to decide if adding a cluster is worthwhile
 */
int
nfsrv_rephead(
	struct nfsrv_descript *nd,
	__unused struct nfsrv_sock *slp,
	struct nfsm_chain *nmrepp,
	size_t siz)
{
	mbuf_t mrep;
	u_long *tl;
	struct nfsm_chain nmrep;
	int err, error;

	err = nd->nd_repstat;
	if (err && (nd->nd_vers == NFS_VER2))
		siz = 0;

	/*
	 * If this is a big reply, use a cluster else
	 * try and leave leading space for the lower level headers.
	 */
	siz += RPC_REPLYSIZ;
	if (siz >= nfs_mbuf_minclsize) {
		error = mbuf_getpacket(MBUF_WAITOK, &mrep);
	} else {
		error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &mrep);
	}
	if (error) {
		/* unable to allocate packet */
		/* XXX should we keep statistics for these errors? */
		return (error);
	}
	if (siz < nfs_mbuf_minclsize) {
		/* leave space for lower level headers */
		tl = mbuf_data(mrep);
		tl += 80/sizeof(*tl);  /* XXX max_hdr? XXX */
		mbuf_setdata(mrep, tl, 6 * NFSX_UNSIGNED);
	}
	nfsm_chain_init(&nmrep, mrep);
	nfsm_chain_add_32(error, &nmrep, nd->nd_retxid);
	nfsm_chain_add_32(error, &nmrep, RPC_REPLY);
	if (err == ERPCMISMATCH || (err & NFSERR_AUTHERR)) {
		nfsm_chain_add_32(error, &nmrep, RPC_MSGDENIED);
		if (err & NFSERR_AUTHERR) {
			nfsm_chain_add_32(error, &nmrep, RPC_AUTHERR);
			nfsm_chain_add_32(error, &nmrep, (err & ~NFSERR_AUTHERR));
		} else {
			nfsm_chain_add_32(error, &nmrep, RPC_MISMATCH);
			nfsm_chain_add_32(error, &nmrep, RPC_VER2);
			nfsm_chain_add_32(error, &nmrep, RPC_VER2);
		}
	} else {
		/* reply status */
		nfsm_chain_add_32(error, &nmrep, RPC_MSGACCEPTED);
		if (nd->nd_gss_context != NULL) {
			/* RPCSEC_GSS verifier */
			error = nfs_gss_svc_verf_put(nd, &nmrep);
			if (error) {
				nfsm_chain_add_32(error, &nmrep, RPC_SYSTEM_ERR);
				goto done;
			}
		} else {
			/* RPCAUTH_NULL verifier */
			nfsm_chain_add_32(error, &nmrep, RPCAUTH_NULL);
			nfsm_chain_add_32(error, &nmrep, 0);
		}
		/* accepted status */
		switch (err) {
		case EPROGUNAVAIL:
			nfsm_chain_add_32(error, &nmrep, RPC_PROGUNAVAIL);
			break;
		case EPROGMISMATCH:
			nfsm_chain_add_32(error, &nmrep, RPC_PROGMISMATCH);
			/* XXX hard coded versions? */
			nfsm_chain_add_32(error, &nmrep, NFS_VER2);
			nfsm_chain_add_32(error, &nmrep, NFS_VER3);
			break;
		case EPROCUNAVAIL:
			nfsm_chain_add_32(error, &nmrep, RPC_PROCUNAVAIL);
			break;
		case EBADRPC:
			nfsm_chain_add_32(error, &nmrep, RPC_GARBAGE);
			break;
		default:
			nfsm_chain_add_32(error, &nmrep, RPC_SUCCESS);
			if (nd->nd_gss_context != NULL)
				error = nfs_gss_svc_prepare_reply(nd, &nmrep);
			if (err != NFSERR_RETVOID)
				nfsm_chain_add_32(error, &nmrep,
					(err ? nfsrv_errmap(nd, err) : 0));
			break;
		}
	}

done:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		/* error composing reply header */
		/* XXX should we keep statistics for these errors? */
		mbuf_freem(mrep);
		return (error);
	}

	*nmrepp = nmrep;
	if ((err != 0) && (err != NFSERR_RETVOID))
		OSAddAtomic(1, (SInt32*)&nfsstats.srvrpc_errs);
	return (0);
}

/*
 * The nfs server send routine.
 *
 * - return EINTR or ERESTART if interrupted by a signal
 * - return EPIPE if a connection is lost for connection based sockets (TCP...)
 * - do any cleanup required by recoverable socket errors (???)
 */
int
nfsrv_send(struct nfsrv_sock *slp, mbuf_t nam, mbuf_t top)
{
	int error;
	socket_t so = slp->ns_so;
	struct sockaddr *sendnam;
	struct msghdr msg;

	bzero(&msg, sizeof(msg));
	if (nam && !sock_isconnected(so) && (slp->ns_sotype != SOCK_STREAM)) {
		if ((sendnam = mbuf_data(nam))) {
			msg.msg_name = (caddr_t)sendnam;
			msg.msg_namelen = sendnam->sa_len;
		}
	}
	error = sock_sendmbuf(so, &msg, top, 0, NULL);
	if (!error)
		return (0);
	log(LOG_INFO, "nfsd send error %d\n", error);

	if ((error == EWOULDBLOCK) && (slp->ns_sotype == SOCK_STREAM))
		error = EPIPE;  /* zap TCP sockets if they time out on send */

	/* Handle any recoverable (soft) socket errors here. (???) */
	if (error != EINTR && error != ERESTART && error != EIO &&
		error != EWOULDBLOCK && error != EPIPE)
		error = 0;

	return (error);
}

/*
 * Socket upcall routine for the nfsd sockets.
 * The caddr_t arg is a pointer to the "struct nfsrv_sock".
 * Essentially do as much as possible non-blocking, else punt and it will
 * be called with MBUF_WAITOK from an nfsd.
 */
void
nfsrv_rcv(socket_t so, caddr_t arg, int waitflag)
{
	struct nfsrv_sock *slp = (struct nfsrv_sock *)arg;

	if (!nfsd_thread_count || !(slp->ns_flag & SLP_VALID))
		return;

	lck_rw_lock_exclusive(&slp->ns_rwlock);
	nfsrv_rcv_locked(so, slp, waitflag);
	/* Note: ns_rwlock gets dropped when called with MBUF_DONTWAIT */
}
void
nfsrv_rcv_locked(socket_t so, struct nfsrv_sock *slp, int waitflag)
{
	mbuf_t m, mp, mhck, m2;
	int ns_flag=0, error;
	struct msghdr	msg;
	size_t bytes_read;

	if ((slp->ns_flag & SLP_VALID) == 0) {
		if (waitflag == MBUF_DONTWAIT)
			lck_rw_done(&slp->ns_rwlock);
		return;
	}

#ifdef notdef
	/*
	 * Define this to test for nfsds handling this under heavy load.
	 */
	if (waitflag == MBUF_DONTWAIT) {
		ns_flag = SLP_NEEDQ;
		goto dorecs;
	}
#endif
	if (slp->ns_sotype == SOCK_STREAM) {
		/*
		 * If there are already records on the queue, defer soreceive()
		 * to an nfsd so that there is feedback to the TCP layer that
		 * the nfs servers are heavily loaded.
		 */
		if (slp->ns_rec && waitflag == MBUF_DONTWAIT) {
			ns_flag = SLP_NEEDQ;
			goto dorecs;
		}

		/*
		 * Do soreceive().
		 */
		bytes_read = 1000000000;
		error = sock_receivembuf(so, NULL, &mp, MSG_DONTWAIT, &bytes_read);
		if (error || mp == NULL) {
			if (error == EWOULDBLOCK)
				ns_flag = (waitflag == MBUF_DONTWAIT) ? SLP_NEEDQ : 0;
			else
				ns_flag = SLP_DISCONN;
			goto dorecs;
		}
		m = mp;
		if (slp->ns_rawend) {
			if ((error = mbuf_setnext(slp->ns_rawend, m)))
				panic("nfsrv_rcv: mbuf_setnext failed %d\n", error);
			slp->ns_cc += bytes_read;
		} else {
			slp->ns_raw = m;
			slp->ns_cc = bytes_read;
		}
		while ((m2 = mbuf_next(m)))
			m = m2;
		slp->ns_rawend = m;

		/*
		 * Now try and parse record(s) out of the raw stream data.
		 */
		error = nfsrv_getstream(slp, waitflag);
		if (error) {
			if (error == EPERM)
				ns_flag = SLP_DISCONN;
			else
				ns_flag = SLP_NEEDQ;
		}
	} else {
		struct sockaddr_storage	nam;

		if (slp->ns_reccnt >= nfsrv_sock_max_rec_queue_length) {
			/* already have max # RPC records queued on this socket */
			ns_flag = SLP_NEEDQ;
			goto dorecs;
		}
		
		bzero(&msg, sizeof(msg));
		msg.msg_name = (caddr_t)&nam;
		msg.msg_namelen = sizeof(nam);
		
		do {
			bytes_read = 1000000000;
			error = sock_receivembuf(so, &msg, &mp, MSG_DONTWAIT | MSG_NEEDSA, &bytes_read);
			if (mp) {
				if (msg.msg_name && (mbuf_get(MBUF_WAITOK, MBUF_TYPE_SONAME, &mhck) == 0)) {
					mbuf_setlen(mhck, nam.ss_len);
					bcopy(&nam, mbuf_data(mhck), nam.ss_len);
					m = mhck;
					if (mbuf_setnext(m, mp)) {
						/* trouble... just drop it */
						printf("nfsrv_rcv: mbuf_setnext failed\n");
						mbuf_free(mhck);
						m = mp;
					}
				} else {
					m = mp;
				}
				if (slp->ns_recend)
					mbuf_setnextpkt(slp->ns_recend, m);
				else {
					slp->ns_rec = m;
					slp->ns_flag |= SLP_DOREC;
				}
				slp->ns_recend = m;
				mbuf_setnextpkt(m, NULL);
				slp->ns_reccnt++;
			}
		} while (mp);
	}

	/*
	 * Now try and process the request records, non-blocking.
	 */
dorecs:
	if (ns_flag)
		slp->ns_flag |= ns_flag;
	if (waitflag == MBUF_DONTWAIT) {
		int wake = (slp->ns_flag & SLP_WORKTODO);
		lck_rw_done(&slp->ns_rwlock);
		if (wake && nfsd_thread_count) {
			lck_mtx_lock(nfsd_mutex);
			nfsrv_wakenfsd(slp);
			lck_mtx_unlock(nfsd_mutex);
		}
	}
}

/*
 * Try and extract an RPC request from the mbuf data list received on a
 * stream socket. The "waitflag" argument indicates whether or not it
 * can sleep.
 */
static int
nfsrv_getstream(struct nfsrv_sock *slp, int waitflag)
{
	mbuf_t m;
	char *cp1, *cp2, *mdata;
	int len, mlen, error;
	mbuf_t om, m2, recm;
	u_long recmark;

	if (slp->ns_flag & SLP_GETSTREAM)
		panic("nfs getstream");
	slp->ns_flag |= SLP_GETSTREAM;
	for (;;) {
	    if (slp->ns_reclen == 0) {
		if (slp->ns_cc < NFSX_UNSIGNED) {
			slp->ns_flag &= ~SLP_GETSTREAM;
			return (0);
		}
		m = slp->ns_raw;
		mdata = mbuf_data(m);
		mlen = mbuf_len(m);
		if (mlen >= NFSX_UNSIGNED) {
			bcopy(mdata, (caddr_t)&recmark, NFSX_UNSIGNED);
			mdata += NFSX_UNSIGNED;
			mlen -= NFSX_UNSIGNED;
			mbuf_setdata(m, mdata, mlen);
		} else {
			cp1 = (caddr_t)&recmark;
			cp2 = mdata;
			while (cp1 < ((caddr_t)&recmark) + NFSX_UNSIGNED) {
				while (mlen == 0) {
					m = mbuf_next(m);
					cp2 = mbuf_data(m);
					mlen = mbuf_len(m);
				}
				*cp1++ = *cp2++;
				mlen--;
				mbuf_setdata(m, cp2, mlen);
			}
		}
		slp->ns_cc -= NFSX_UNSIGNED;
		recmark = ntohl(recmark);
		slp->ns_reclen = recmark & ~0x80000000;
		if (recmark & 0x80000000)
			slp->ns_flag |= SLP_LASTFRAG;
		else
			slp->ns_flag &= ~SLP_LASTFRAG;
		if (slp->ns_reclen < NFS_MINPACKET || slp->ns_reclen > NFS_MAXPACKET) {
			slp->ns_flag &= ~SLP_GETSTREAM;
			return (EPERM);
		}
	    }

	    /*
	     * Now get the record part.
	     *
	     * Note that slp->ns_reclen may be 0.  Linux sometimes
	     * generates 0-length RPCs
	     */
	    recm = NULL;
	    if (slp->ns_cc == slp->ns_reclen) {
		recm = slp->ns_raw;
		slp->ns_raw = slp->ns_rawend = NULL;
		slp->ns_cc = slp->ns_reclen = 0;
	    } else if (slp->ns_cc > slp->ns_reclen) {
		len = 0;
		m = slp->ns_raw;
		mlen = mbuf_len(m);
		mdata = mbuf_data(m);
		om = NULL;
		while (len < slp->ns_reclen) {
			if ((len + mlen) > slp->ns_reclen) {
				if (mbuf_copym(m, 0, slp->ns_reclen - len, waitflag, &m2)) {
					slp->ns_flag &= ~SLP_GETSTREAM;
					return (EWOULDBLOCK);
				}
				if (om) {
					if (mbuf_setnext(om, m2)) {
						/* trouble... just drop it */
						printf("nfsrv_getstream: mbuf_setnext failed\n");
						mbuf_freem(m2);
						slp->ns_flag &= ~SLP_GETSTREAM;
						return (EWOULDBLOCK);
					}
					recm = slp->ns_raw;
				} else {
					recm = m2;
				}
				mdata += slp->ns_reclen - len;
				mlen -= slp->ns_reclen - len;
				mbuf_setdata(m, mdata, mlen);
				len = slp->ns_reclen;
			} else if ((len + mlen) == slp->ns_reclen) {
				om = m;
				len += mlen;
				m = mbuf_next(m);
				recm = slp->ns_raw;
				if (mbuf_setnext(om, NULL)) {
					printf("nfsrv_getstream: mbuf_setnext failed 2\n");
					slp->ns_flag &= ~SLP_GETSTREAM;
					return (EWOULDBLOCK);
				}
				mlen = mbuf_len(m);
				mdata = mbuf_data(m);
			} else {
				om = m;
				len += mlen;
				m = mbuf_next(m);
				mlen = mbuf_len(m);
				mdata = mbuf_data(m);
			}
		}
		slp->ns_raw = m;
		slp->ns_cc -= len;
		slp->ns_reclen = 0;
	    } else {
		slp->ns_flag &= ~SLP_GETSTREAM;
		return (0);
	    }

	    /*
	     * Accumulate the fragments into a record.
	     */
	    if (slp->ns_frag == NULL) {
		slp->ns_frag = recm;
	    } else {
	        m = slp->ns_frag;
		while ((m2 = mbuf_next(m)))
		    m = m2;
		if ((error = mbuf_setnext(m, recm)))
		    panic("nfsrv_getstream: mbuf_setnext failed 3, %d\n", error);
	    }
	    if (slp->ns_flag & SLP_LASTFRAG) {
		if (slp->ns_recend)
		    mbuf_setnextpkt(slp->ns_recend, slp->ns_frag);
		else {
		    slp->ns_rec = slp->ns_frag;
		    slp->ns_flag |= SLP_DOREC;
		}
		slp->ns_recend = slp->ns_frag;
		slp->ns_frag = NULL;
	    }
	}
}

/*
 * Parse an RPC header.
 */
int
nfsrv_dorec(
	struct nfsrv_sock *slp,
	struct nfsd *nfsd,
	struct nfsrv_descript **ndp)
{
	mbuf_t m;
	mbuf_t nam;
	struct nfsrv_descript *nd;
	int error = 0;

	*ndp = NULL;
	if (!(slp->ns_flag & (SLP_VALID|SLP_DOREC)) || (slp->ns_rec == NULL))
		return (ENOBUFS);
	MALLOC_ZONE(nd, struct nfsrv_descript *,
			sizeof (struct nfsrv_descript), M_NFSRVDESC, M_WAITOK);
	if (!nd)
		return (ENOMEM);
	m = slp->ns_rec;
	slp->ns_rec = mbuf_nextpkt(m);
	if (slp->ns_rec)
		mbuf_setnextpkt(m, NULL);
	else {
		slp->ns_flag &= ~SLP_DOREC;
		slp->ns_recend = NULL;
	}
	slp->ns_reccnt--;
	if (mbuf_type(m) == MBUF_TYPE_SONAME) {
		nam = m;
		m = mbuf_next(m);
		if ((error = mbuf_setnext(nam, NULL)))
			panic("nfsrv_dorec: mbuf_setnext failed %d\n", error);
	} else
		nam = NULL;
	nd->nd_nam2 = nam;
	nfsm_chain_dissect_init(error, &nd->nd_nmreq, m);
	if (!error)
		error = nfsrv_getreq(nd);
	if (error) {
		if (nam)
			mbuf_freem(nam);
		FREE_ZONE(nd, sizeof(*nd), M_NFSRVDESC);
		return (error);
	}
	nd->nd_mrep = NULL;
	*ndp = nd;
	nfsd->nfsd_nd = nd;
	return (0);
}

/*
 * Parse an RPC request
 * - verify it
 * - fill in the cred struct.
 */
static int
nfsrv_getreq(struct nfsrv_descript *nd)
{
	struct nfsm_chain *nmreq;
	int len, i;
	u_long nfsvers, auth_type;
	int error = 0;
	uid_t user_id;
	gid_t group_id;
	int ngroups;
	struct ucred temp_cred;
	uint32_t val;

	nd->nd_cr = NULL;
	nd->nd_gss_context = NULL;
	nd->nd_gss_seqnum = 0;
	nd->nd_gss_mb = NULL;

	user_id = group_id = -2;
	val = auth_type = len = 0;

	nmreq = &nd->nd_nmreq;
	nfsm_chain_get_32(error, nmreq, nd->nd_retxid);	// XID
	nfsm_chain_get_32(error, nmreq, val);		// RPC Call
	if (!error && (val != RPC_CALL))
		error = EBADRPC;
	nfsmout_if(error);
	nd->nd_repstat = 0;
	nfsm_chain_get_32(error, nmreq, val);	// RPC Version
	nfsmout_if(error);
	if (val != RPC_VER2) {
		nd->nd_repstat = ERPCMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	nfsm_chain_get_32(error, nmreq, val);	// RPC Program Number
	nfsmout_if(error);
	if (val != NFS_PROG) {
		nd->nd_repstat = EPROGUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	nfsm_chain_get_32(error, nmreq, nfsvers);// NFS Version Number
	nfsmout_if(error);
	if ((nfsvers < NFS_VER2) || (nfsvers > NFS_VER3)) {
		nd->nd_repstat = EPROGMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	nd->nd_vers = nfsvers;
	nfsm_chain_get_32(error, nmreq, nd->nd_procnum);// NFS Procedure Number
	nfsmout_if(error);
	if ((nd->nd_procnum >= NFS_NPROCS) ||
		((nd->nd_vers == NFS_VER2) && (nd->nd_procnum > NFSV2PROC_STATFS))) {
		nd->nd_repstat = EPROCUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	if (nfsvers != NFS_VER3)
		nd->nd_procnum = nfsv3_procid[nd->nd_procnum];
	nfsm_chain_get_32(error, nmreq, auth_type);	// Auth Flavor
	nfsm_chain_get_32(error, nmreq, len);		// Auth Length
	if (!error && (len < 0 || len > RPCAUTH_MAXSIZ))
		error = EBADRPC;
	nfsmout_if(error);

	/* Handle authentication */
	if (auth_type == RPCAUTH_UNIX) {
		if (nd->nd_procnum == NFSPROC_NULL)
			return (0);
		nd->nd_sec = RPCAUTH_UNIX;
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);	// skip stamp
		nfsm_chain_get_32(error, nmreq, len);		// hostname length
		if (len < 0 || len > NFS_MAXNAMLEN)
			error = EBADRPC;
		nfsm_chain_adv(error, nmreq, nfsm_rndup(len));	// skip hostname
		nfsmout_if(error);

		/* create a temporary credential using the bits from the wire */
		bzero(&temp_cred, sizeof(temp_cred));
		nfsm_chain_get_32(error, nmreq, user_id);
		nfsm_chain_get_32(error, nmreq, group_id);
		temp_cred.cr_groups[0] = group_id;
		nfsm_chain_get_32(error, nmreq, len);		// extra GID count
		if ((len < 0) || (len > RPCAUTH_UNIXGIDS))
			error = EBADRPC;
		nfsmout_if(error);
		for (i = 1; i <= len; i++)
			if (i < NGROUPS)
				nfsm_chain_get_32(error, nmreq, temp_cred.cr_groups[i]);
			else
				nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		nfsmout_if(error);
		ngroups = (len >= NGROUPS) ? NGROUPS : (len + 1);
		if (ngroups > 1)
			nfsrv_group_sort(&temp_cred.cr_groups[0], ngroups);
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);	// verifier flavor (should be AUTH_NONE)
		nfsm_chain_get_32(error, nmreq, len);		// verifier length
		if (len < 0 || len > RPCAUTH_MAXSIZ)
			error = EBADRPC;
		if (len > 0)
			nfsm_chain_adv(error, nmreq, nfsm_rndup(len));

		/* request creation of a real credential */
		temp_cred.cr_uid = user_id;
		temp_cred.cr_ngroups = ngroups;
		nd->nd_cr = kauth_cred_create(&temp_cred);
		if (nd->nd_cr == NULL) {
			nd->nd_repstat = ENOMEM;
			nd->nd_procnum = NFSPROC_NOOP;
			return (0);
		}
	} else if (auth_type == RPCSEC_GSS) {
		error = nfs_gss_svc_cred_get(nd, nmreq);
		if (error) {
			if (error == EINVAL)
				goto nfsmout;	// drop the request
			nd->nd_repstat = error;
			nd->nd_procnum = NFSPROC_NOOP;
			return (0);
		}
	} else {
		if (nd->nd_procnum == NFSPROC_NULL)	// assume it's AUTH_NONE
			return (0);
		nd->nd_repstat = (NFSERR_AUTHERR | AUTH_REJECTCRED);
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	return (0);
nfsmout:
	if (IS_VALID_CRED(nd->nd_cr))
		kauth_cred_unref(&nd->nd_cr);
	nfsm_chain_cleanup(nmreq);
	return (error);
}

/*
 * Search for a sleeping nfsd and wake it up.
 * SIDE EFFECT: If none found, make sure the socket is queued up so that one
 * of the running nfsds will go look for the work in the nfsrv_sockwait list.
 * Note: Must be called with nfsd_mutex held.
 */
void
nfsrv_wakenfsd(struct nfsrv_sock *slp)
{
	struct nfsd *nd;

	if ((slp->ns_flag & SLP_VALID) == 0)
		return;

	lck_rw_lock_exclusive(&slp->ns_rwlock);
	/* if there's work to do on this socket, make sure it's queued up */
	if ((slp->ns_flag & SLP_WORKTODO) && !(slp->ns_flag & SLP_QUEUED)) {
		TAILQ_INSERT_TAIL(&nfsrv_sockwait, slp, ns_svcq);
		slp->ns_flag |= SLP_WAITQ;
	}
	lck_rw_done(&slp->ns_rwlock);

	/* wake up a waiting nfsd, if possible */
	nd = TAILQ_FIRST(&nfsd_queue);
	if (!nd)
		return;

	TAILQ_REMOVE(&nfsd_queue, nd, nfsd_queue);
	nd->nfsd_flag &= ~NFSD_WAITING;
	wakeup(nd);
}

#endif /* NFSSERVER */

static int
nfs_msg(thread_t thd,
	const char *server,
	const char *msg,
	int error)
{
	proc_t p = thd ? get_bsdthreadtask_info(thd) : NULL;
	tpr_t tpr;

	if (p)
		tpr = tprintf_open(p);
	else
		tpr = NULL;
	if (error)
		tprintf(tpr, "nfs server %s: %s, error %d\n", server, msg, error);
	else
		tprintf(tpr, "nfs server %s: %s\n", server, msg);
	tprintf_close(tpr);
	return (0);
}

void
nfs_down(struct nfsmount *nmp, thread_t thd, int error, int flags, const char *msg)
{
	int ostate;

	if (nmp == NULL)
		return;

	lck_mtx_lock(&nmp->nm_lock);
	ostate = nmp->nm_state;
	if ((flags & NFSSTA_TIMEO) && !(ostate & NFSSTA_TIMEO))
		nmp->nm_state |= NFSSTA_TIMEO;
	if ((flags & NFSSTA_LOCKTIMEO) && !(ostate & NFSSTA_LOCKTIMEO))
		nmp->nm_state |= NFSSTA_LOCKTIMEO;
	if ((flags & NFSSTA_JUKEBOXTIMEO) && !(ostate & NFSSTA_JUKEBOXTIMEO))
		nmp->nm_state |= NFSSTA_JUKEBOXTIMEO;
	lck_mtx_unlock(&nmp->nm_lock);

	if (!(ostate & (NFSSTA_TIMEO|NFSSTA_LOCKTIMEO|NFSSTA_JUKEBOXTIMEO)))
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESP, 0);

	nfs_msg(thd, vfs_statfs(nmp->nm_mountp)->f_mntfromname, msg, error);
}

void
nfs_up(struct nfsmount *nmp, thread_t thd, int flags, const char *msg)
{
	int ostate, state;

	if (nmp == NULL)
		return;

	if (msg)
		nfs_msg(thd, vfs_statfs(nmp->nm_mountp)->f_mntfromname, msg, 0);

	lck_mtx_lock(&nmp->nm_lock);
	ostate = nmp->nm_state;
	if ((flags & NFSSTA_TIMEO) && (ostate & NFSSTA_TIMEO))
		nmp->nm_state &= ~NFSSTA_TIMEO;
	if ((flags & NFSSTA_LOCKTIMEO) && (ostate & NFSSTA_LOCKTIMEO))
		nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
	if ((flags & NFSSTA_JUKEBOXTIMEO) && (ostate & NFSSTA_JUKEBOXTIMEO))
		nmp->nm_state &= ~NFSSTA_JUKEBOXTIMEO;
	state = nmp->nm_state;
	lck_mtx_unlock(&nmp->nm_lock);

	if ((ostate & (NFSSTA_TIMEO|NFSSTA_LOCKTIMEO|NFSSTA_JUKEBOXTIMEO)) &&
	    !(state & (NFSSTA_TIMEO|NFSSTA_LOCKTIMEO|NFSSTA_JUKEBOXTIMEO)))
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESP, 1);
}

