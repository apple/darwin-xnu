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
#include <sys/user.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsrtt.h>

#include <sys/kdebug.h>

#define FSDBG(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_NONE, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_TOP(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_START, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_BOT(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_END, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)

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
 * External data, mostly RPC constants in XDR form
 */
extern u_long rpc_reply, rpc_msgdenied, rpc_mismatch, rpc_vers, rpc_auth_unix,
	rpc_msgaccepted, rpc_call, rpc_autherr,
	rpc_auth_kerb;
extern u_long nfs_prog;
extern struct nfsstats nfsstats;
extern int nfsv3_procid[NFS_NPROCS];
extern int nfs_ticks;
extern u_long nfs_xidwrap;

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
int nfsrtton = 0;
struct nfsrtt nfsrtt;

static int	nfs_rcvlock(struct nfsreq *);
static void	nfs_rcvunlock(struct nfsreq *);
static int	nfs_receive(struct nfsreq *rep, mbuf_t *mp);
static int	nfs_reconnect(struct nfsreq *rep);
static void	nfs_repdequeue(struct nfsreq *rep);

/* XXX */
boolean_t	current_thread_aborted(void);
kern_return_t	thread_terminate(thread_t);

#ifndef NFS_NOSERVER 
static int	nfsrv_getstream(struct nfssvc_sock *,int);

int (*nfsrv3_procs[NFS_NPROCS])(struct nfsrv_descript *nd,
				    struct nfssvc_sock *slp,
				    proc_t procp,
				    mbuf_t *mreqp) = {
	nfsrv_null,
	nfsrv_getattr,
	nfsrv_setattr,
	nfsrv_lookup,
	nfsrv3_access,
	nfsrv_readlink,
	nfsrv_read,
	nfsrv_write,
	nfsrv_create,
	nfsrv_mkdir,
	nfsrv_symlink,
	nfsrv_mknod,
	nfsrv_remove,
	nfsrv_rmdir,
	nfsrv_rename,
	nfsrv_link,
	nfsrv_readdir,
	nfsrv_readdirplus,
	nfsrv_statfs,
	nfsrv_fsinfo,
	nfsrv_pathconf,
	nfsrv_commit,
	nfsrv_noop
};
#endif /* NFS_NOSERVER */


/*
 * attempt to bind a socket to a reserved port
 */
static int
nfs_bind_resv(struct nfsmount *nmp)
{
	socket_t so = nmp->nm_so;
	struct sockaddr_in sin;
	int error;
	u_short tport;

	if (!so)
		return (EINVAL);

	sin.sin_len = sizeof (struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	tport = IPPORT_RESERVED - 1;
	sin.sin_port = htons(tport);

	while (((error = sock_bind(so, (struct sockaddr *) &sin)) == EADDRINUSE) &&
	       (--tport > IPPORT_RESERVED / 2))
		sin.sin_port = htons(tport);
	return (error);
}

/*
 * variables for managing the nfs_bind_resv_thread
 */
int nfs_resv_mounts = 0;
static int nfs_bind_resv_thread_state = 0;
#define NFS_BIND_RESV_THREAD_STATE_INITTED	1
#define NFS_BIND_RESV_THREAD_STATE_RUNNING	2
lck_grp_t *nfs_bind_resv_lck_grp;
lck_grp_attr_t *nfs_bind_resv_lck_grp_attr;
lck_attr_t *nfs_bind_resv_lck_attr;
lck_mtx_t *nfs_bind_resv_mutex;
struct nfs_bind_resv_request {
	TAILQ_ENTRY(nfs_bind_resv_request) brr_chain;
	struct nfsmount *brr_nmp;
	int brr_error;
};
static TAILQ_HEAD(, nfs_bind_resv_request) nfs_bind_resv_request_queue;

/*
 * thread to handle any reserved port bind requests
 */
static void
nfs_bind_resv_thread(void)
{
	struct nfs_bind_resv_request *brreq;

	nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_RUNNING;

	while (nfs_resv_mounts > 0) {
		lck_mtx_lock(nfs_bind_resv_mutex);
		while ((brreq = TAILQ_FIRST(&nfs_bind_resv_request_queue))) {
			TAILQ_REMOVE(&nfs_bind_resv_request_queue, brreq, brr_chain);
			lck_mtx_unlock(nfs_bind_resv_mutex);
			brreq->brr_error = nfs_bind_resv(brreq->brr_nmp);
			wakeup(brreq);
			lck_mtx_lock(nfs_bind_resv_mutex);
		}
		msleep((caddr_t)&nfs_bind_resv_request_queue,
				nfs_bind_resv_mutex, PSOCK | PDROP,
				"nfs_bind_resv_request_queue", 0);
	}

	nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_INITTED;
	(void) thread_terminate(current_thread());
}

int
nfs_bind_resv_thread_wake(void)
{
	if (nfs_bind_resv_thread_state < NFS_BIND_RESV_THREAD_STATE_RUNNING)
		return (EIO);
	wakeup(&nfs_bind_resv_request_queue);
	return (0);
}

/*
 * underprivileged procs call this to request nfs_bind_resv_thread
 * to perform the reserved port binding for them.
 */
static int
nfs_bind_resv_nopriv(struct nfsmount *nmp)
{
	struct nfs_bind_resv_request brreq;
	int error;

	if (nfs_bind_resv_thread_state < NFS_BIND_RESV_THREAD_STATE_RUNNING) {
		if (nfs_bind_resv_thread_state < NFS_BIND_RESV_THREAD_STATE_INITTED) {
			nfs_bind_resv_lck_grp_attr = lck_grp_attr_alloc_init();
			lck_grp_attr_setstat(nfs_bind_resv_lck_grp_attr);
			nfs_bind_resv_lck_grp = lck_grp_alloc_init("nfs_bind_resv", nfs_bind_resv_lck_grp_attr);
			nfs_bind_resv_lck_attr = lck_attr_alloc_init();
			nfs_bind_resv_mutex = lck_mtx_alloc_init(nfs_bind_resv_lck_grp, nfs_bind_resv_lck_attr);
			TAILQ_INIT(&nfs_bind_resv_request_queue);
			nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_INITTED;
		}
		kernel_thread(kernel_task, nfs_bind_resv_thread);
		nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_RUNNING;
	}

	brreq.brr_nmp = nmp;
	brreq.brr_error = 0;

	lck_mtx_lock(nfs_bind_resv_mutex);
	TAILQ_INSERT_TAIL(&nfs_bind_resv_request_queue, &brreq, brr_chain);
	lck_mtx_unlock(nfs_bind_resv_mutex);

	error = nfs_bind_resv_thread_wake();
	if (error) {
		TAILQ_REMOVE(&nfs_bind_resv_request_queue, &brreq, brr_chain);
		/* Note: we might be able to simply restart the thread */
		return (error);
	}

	tsleep((caddr_t)&brreq, PSOCK, "nfsbindresv", 0);

	return (brreq.brr_error);
}

/*
 * Initialize sockets and congestion for a new NFS connection.
 * We do not free the sockaddr if error.
 */
int
nfs_connect(
	struct nfsmount *nmp,
	__unused struct nfsreq *rep)
{
	socket_t so;
	int error, rcvreserve, sndreserve;
	struct sockaddr *saddr;
	struct timeval timeo;

	nmp->nm_so = 0;
	saddr = mbuf_data(nmp->nm_nam);
	error = sock_socket(saddr->sa_family, nmp->nm_sotype,
						nmp->nm_soproto, 0, 0, &nmp->nm_so);
	if (error) {
		goto bad;
	}
	so = nmp->nm_so;

	/*
	 * Some servers require that the client port be a reserved port number.
	 */
	if (saddr->sa_family == AF_INET && (nmp->nm_flag & NFSMNT_RESVPORT)) {
		proc_t p;
		/*
		 * sobind() requires current_proc() to have superuser privs.
		 * If this bind is part of a reconnect, and the current proc
		 * doesn't have superuser privs, we hand the sobind() off to
		 * a kernel thread to process.
		 */
		if ((nmp->nm_state & NFSSTA_MOUNTED) &&
		    (p = current_proc()) && suser(kauth_cred_get(), 0)) {
			/* request nfs_bind_resv_thread() to do bind */
			error = nfs_bind_resv_nopriv(nmp);
		} else {
			error = nfs_bind_resv(nmp);
		}
		if (error)
			goto bad;
	}

	/*
	 * Protocols that do not require connections may be optionally left
	 * unconnected for servers that reply from a port other than NFS_PORT.
	 */
	if (nmp->nm_flag & NFSMNT_NOCONN) {
		if (nmp->nm_sotype == SOCK_STREAM) {
			error = ENOTCONN;
			goto bad;
		}
	} else {
		struct timeval	tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		error = sock_connect(so, mbuf_data(nmp->nm_nam), MSG_DONTWAIT);
		if (error && error != EINPROGRESS) {
			goto bad;
		}
		
		while ((error = sock_connectwait(so, &tv)) == EINPROGRESS) {
			if (rep && (error = nfs_sigintr(nmp, rep, rep->r_procp))) {
				goto bad;
			}
		}
	}
	
	/*
	 * Always time out on recieve, this allows us to reconnect the
	 * socket to deal with network changes.
	 */
	timeo.tv_usec = 0;
	timeo.tv_sec = 2;
	error = sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
	if (nmp->nm_flag & (NFSMNT_SOFT | NFSMNT_INT)) {
		timeo.tv_sec = 5;
	} else {
		timeo.tv_sec = 0;
	}
	error = sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
	
	if (nmp->nm_sotype == SOCK_DGRAM) {
		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR) *
			(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	} else if (nmp->nm_sotype == SOCK_SEQPACKET) {
		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR) *
			(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	} else {
		int proto;
		int on = 1;
		
		sock_gettype(so, NULL, NULL, &proto);
		if (nmp->nm_sotype != SOCK_STREAM)
			panic("nfscon sotype");

		// Assume that SOCK_STREAM always requires a connection
		sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
		
		if (proto == IPPROTO_TCP) {
			sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
		}

		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR + sizeof (u_long)) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR + sizeof (u_long)) *
				(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	}

	if (sndreserve > NFS_MAXSOCKBUF)
		sndreserve = NFS_MAXSOCKBUF;
	if (rcvreserve > NFS_MAXSOCKBUF)
		rcvreserve = NFS_MAXSOCKBUF;
	error = sock_setsockopt(so, SOL_SOCKET, SO_SNDBUF, &sndreserve, sizeof(sndreserve));
	if (error) {
		goto bad;
	}
	error = sock_setsockopt(so, SOL_SOCKET, SO_RCVBUF, &rcvreserve, sizeof(rcvreserve));
	if (error) {
		goto bad;
	}

	sock_nointerrupt(so, 1);

	/* Initialize other non-zero congestion variables */
	nmp->nm_srtt[0] = nmp->nm_srtt[1] = nmp->nm_srtt[2] =
		nmp->nm_srtt[3] = (NFS_TIMEO << 3);
	nmp->nm_sdrtt[0] = nmp->nm_sdrtt[1] = nmp->nm_sdrtt[2] =
		nmp->nm_sdrtt[3] = 0;
	nmp->nm_cwnd = NFS_MAXCWND / 2;	    /* Initial send window */
	nmp->nm_sent = 0;
	FSDBG(529, nmp, nmp->nm_state, nmp->nm_soflags, nmp->nm_cwnd);
	nmp->nm_timeouts = 0;
	return (0);

bad:
	nfs_disconnect(nmp);
	return (error);
}

/*
 * Reconnect routine:
 * Called when a connection is broken on a reliable protocol.
 * - clean up the old socket
 * - nfs_connect() again
 * - set R_MUSTRESEND for all outstanding requests on mount point
 * If this fails the mount point is DEAD!
 * nb: Must be called with the nfs_sndlock() set on the mount point.
 */
static int
nfs_reconnect(struct nfsreq *rep)
{
	struct nfsreq *rp;
	struct nfsmount *nmp = rep->r_nmp;
	int error;

	nfs_disconnect(nmp);
	while ((error = nfs_connect(nmp, rep))) {
		if (error == EINTR || error == ERESTART)
			return (EINTR);
		if (error == EIO)
			return (EIO);
		nfs_down(rep->r_nmp, rep->r_procp, error, NFSSTA_TIMEO,
			"can not connect");
		rep->r_flags |= R_TPRINTFMSG;
		if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
			/* we're not yet completely mounted and */
			/* we can't reconnect, so we fail */
			return (error);
		}
		if ((error = nfs_sigintr(rep->r_nmp, rep, rep->r_procp)))
			return (error);
		tsleep((caddr_t)&lbolt, PSOCK, "nfscon", 0);
	}

	/*
	 * Loop through outstanding request list and fix up all requests
	 * on old socket.
	 */
	TAILQ_FOREACH(rp, &nfs_reqq, r_chain) {
		if (rp->r_nmp == nmp)
			rp->r_flags |= R_MUSTRESEND;
	}
	return (0);
}

/*
 * NFS disconnect. Clean up and unlink.
 */
void
nfs_disconnect(struct nfsmount *nmp)
{
	socket_t so;

	if (nmp->nm_so) {
		so = nmp->nm_so;
		nmp->nm_so = 0;
		sock_shutdown(so, 2);
		sock_close(so);
	}
}

/*
 * This is the nfs send routine. For connection based socket types, it
 * must be called with an nfs_sndlock() on the socket.
 * "rep == NULL" indicates that it has been called from a server.
 * For the client side:
 * - return EINTR if the RPC is terminated, 0 otherwise
 * - set R_MUSTRESEND if the send fails for any reason
 * - do any cleanup required by recoverable socket errors (???)
 * For the server side:
 * - return EINTR or ERESTART if interrupted by a signal
 * - return EPIPE if a connection is lost for connection based sockets (TCP...)
 * - do any cleanup required by recoverable socket errors (???)
 */
int
nfs_send(so, nam, top, rep)
	socket_t so;
	mbuf_t nam;
	mbuf_t top;
	struct nfsreq *rep;
{
	struct sockaddr *sendnam;
	int error, error2, sotype, flags;
	u_long xidqueued = 0;
	struct nfsreq *rp;
	char savenametolog[MAXPATHLEN];
	struct msghdr msg;
	
	if (rep) {
		error = nfs_sigintr(rep->r_nmp, rep, rep->r_procp);
		if (error) {
			mbuf_freem(top);
			return (error);
		}
		if ((so = rep->r_nmp->nm_so) == NULL) {
			rep->r_flags |= R_MUSTRESEND;
			mbuf_freem(top);
			return (0);
		}
		rep->r_flags &= ~R_MUSTRESEND;
		TAILQ_FOREACH(rp, &nfs_reqq, r_chain)
			if (rp == rep)
				break;
		if (rp)
			xidqueued = rp->r_xid;
	}
	sock_gettype(so, NULL, &sotype, NULL);
	if ((sotype == SOCK_STREAM) || (sock_isconnected(so)) ||
	    (nam == 0))
		sendnam = (struct sockaddr *)0;
	else
		sendnam = mbuf_data(nam);

	if (sotype == SOCK_SEQPACKET)
		flags = MSG_EOR;
	else
		flags = 0;

	/* 
	 * Save the name here in case mount point goes away if we block.
	 * The name is using local stack and is large, but don't
	 * want to block if we malloc.
	 */
	if (rep)
		strncpy(savenametolog,
			vfs_statfs(rep->r_nmp->nm_mountp)->f_mntfromname,
			MAXPATHLEN - 1);
	bzero(&msg, sizeof(msg));
	msg.msg_name = (caddr_t)sendnam;
	msg.msg_namelen = sendnam == 0 ? 0 : sendnam->sa_len;
	error = sock_sendmbuf(so, &msg, top, flags, NULL);

	if (error) {
		if (rep) {
			if (xidqueued) {
				TAILQ_FOREACH(rp, &nfs_reqq, r_chain)
					if (rp == rep && rp->r_xid == xidqueued)
						break;
				if (!rp)
					panic("nfs_send: error %d xid %x gone",
					      error, xidqueued);
			}
			log(LOG_INFO, "nfs send error %d for server %s\n",
			    error, savenametolog);
			/*
			 * Deal with errors for the client side.
			 */
			error2 = nfs_sigintr(rep->r_nmp, rep, rep->r_procp);
			if (error2) {
				error = error2;
			} else {
				rep->r_flags |= R_MUSTRESEND;
			}
		} else
			log(LOG_INFO, "nfsd send error %d\n", error);

		/*
		 * Handle any recoverable (soft) socket errors here. (???)
		 */
		if (error != EINTR && error != ERESTART && error != EIO &&
			error != EWOULDBLOCK && error != EPIPE) {
			error = 0;
		}
	}
	return (error);
}

/*
 * Receive a Sun RPC Request/Reply. For SOCK_DGRAM, the work is all
 * done by soreceive(), but for SOCK_STREAM we must deal with the Record
 * Mark and consolidate the data into a new mbuf list.
 * nb: Sometimes TCP passes the data up to soreceive() in long lists of
 *     small mbufs.
 * For SOCK_STREAM we must be very careful to read an entire record once
 * we have read any of it, even if the system call has been interrupted.
 */
static int
nfs_receive(struct nfsreq *rep, mbuf_t *mp)
{
	socket_t so;
	struct iovec_32 aio;
	mbuf_t m, mlast;
	u_long len, fraglen;
	int error, error2, sotype;
	proc_t p = current_proc();	/* XXX */
	struct msghdr msg;
	size_t rcvlen;
	int lastfragment;

	/*
	 * Set up arguments for soreceive()
	 */
	*mp = NULL;
	sotype = rep->r_nmp->nm_sotype;

	/*
	 * For reliable protocols, lock against other senders/receivers
	 * in case a reconnect is necessary.
	 * For SOCK_STREAM, first get the Record Mark to find out how much
	 * more there is to get.
	 * We must lock the socket against other receivers
	 * until we have an entire rpc request/reply.
	 */
	if (sotype != SOCK_DGRAM) {
		error = nfs_sndlock(rep);
		if (error)
			return (error);
tryagain:
		/*
		 * Check for fatal errors and resending request.
		 */
		/*
		 * Ugh: If a reconnect attempt just happened, nm_so
		 * would have changed. NULL indicates a failed
		 * attempt that has essentially shut down this
		 * mount point.
		 */
		if ((error = nfs_sigintr(rep->r_nmp, rep, p)) || rep->r_mrep) {
			nfs_sndunlock(rep);
			if (error)
				return (error);
			return (EINTR);
		}
		so = rep->r_nmp->nm_so;
		if (!so) {
			error = nfs_reconnect(rep);
			if (error) {
				nfs_sndunlock(rep);
				return (error);
			}
			goto tryagain;
		}
		while (rep->r_flags & R_MUSTRESEND) {
			error = mbuf_copym(rep->r_mreq, 0, MBUF_COPYALL, MBUF_WAITOK, &m);
			if (!error) {
				OSAddAtomic(1, (SInt32*)&nfsstats.rpcretries);
				error = nfs_send(so, rep->r_nmp->nm_nam, m, rep);
			}
			/*
			 * we also hold rcv lock so rep is still
			 * legit this point
			 */
			if (error) {
				if (error == EINTR || error == ERESTART ||
				    (error = nfs_reconnect(rep))) {
					nfs_sndunlock(rep);
					return (error);
				}
				goto tryagain;
			}
		}
		nfs_sndunlock(rep);
		if (sotype == SOCK_STREAM) {
			error = 0;
			len = 0;
			lastfragment = 0;
			mlast = NULL;
			while (!error && !lastfragment) {
				aio.iov_base = (uintptr_t) &fraglen;
				aio.iov_len = sizeof(u_long);
				bzero(&msg, sizeof(msg));
				msg.msg_iov = (struct iovec *) &aio;
				msg.msg_iovlen = 1;
				do {
				   error = sock_receive(so, &msg, MSG_WAITALL, &rcvlen);
				   if (!rep->r_nmp) /* if unmounted then bailout */
					goto shutout;
				   if (error == EWOULDBLOCK && rep) {
					error2 = nfs_sigintr(rep->r_nmp, rep, p);
					if (error2)
						error = error2;
				   }
				} while (error == EWOULDBLOCK);
				if (!error && rcvlen < aio.iov_len) {
				    /* only log a message if we got a partial word */
				    if (rcvlen != 0)
					    log(LOG_INFO,
						 "short receive (%d/%d) from nfs server %s\n",
						 rcvlen, sizeof(u_long),
						 vfs_statfs(rep->r_nmp->nm_mountp)->f_mntfromname);
				    error = EPIPE;
				}
				if (error)
					goto errout;
				lastfragment = ntohl(fraglen) & 0x80000000;
				fraglen = ntohl(fraglen) & ~0x80000000;
				len += fraglen;
				/*
				 * This is SERIOUS! We are out of sync with the sender
				 * and forcing a disconnect/reconnect is all I can do.
				 */
				if (len > NFS_MAXPACKET) {
				    log(LOG_ERR, "%s (%d) from nfs server %s\n",
					"impossible RPC record length", len,
					vfs_statfs(rep->r_nmp->nm_mountp)->f_mntfromname);
				    error = EFBIG;
				    goto errout;
				}

				m = NULL;
				do {
				    rcvlen = fraglen;
				    error = sock_receivembuf(so, NULL, &m, MSG_WAITALL, &rcvlen);
				    if (!rep->r_nmp) /* if unmounted then bailout */ {
					goto shutout;
				    }
				} while (error == EWOULDBLOCK || error == EINTR ||
					 error == ERESTART);

				if (!error && fraglen > rcvlen) {
				    log(LOG_INFO,
					"short receive (%d/%d) from nfs server %s\n",
					rcvlen, fraglen,
					vfs_statfs(rep->r_nmp->nm_mountp)->f_mntfromname);
				    error = EPIPE;
				    mbuf_freem(m);
				}
				if (!error) {
					if (!*mp) {
						*mp = m;
						mlast = m;
					} else {
						error = mbuf_setnext(mlast, m);
						if (error) {
							printf("nfs_receive: mbuf_setnext failed %d\n", error);
							mbuf_freem(m);
						}
					}
					while (mbuf_next(mlast))
						mlast = mbuf_next(mlast);
				}
			}
		} else {
			bzero(&msg, sizeof(msg));
			do {
			    rcvlen = 100000000;
			    error = sock_receivembuf(so, &msg, mp, 0, &rcvlen);
			    if (!rep->r_nmp) /* if unmounted then bailout */ {
				goto shutout;
 			    }   
			    if (error == EWOULDBLOCK && rep) {
				error2 = nfs_sigintr(rep->r_nmp, rep, p);
				if (error2) {
					return (error2);
				}
			    }
			} while (error == EWOULDBLOCK);

			if ((msg.msg_flags & MSG_EOR) == 0)
				printf("Egad!!\n");
			if (!error && *mp == NULL)
				error = EPIPE;
			len = rcvlen;
		}
errout:
		if (error && error != EINTR && error != ERESTART) {
			mbuf_freem(*mp);
			*mp = NULL;
			if (error != EPIPE)
				log(LOG_INFO,
				    "receive error %d from nfs server %s\n", error,
				    vfs_statfs(rep->r_nmp->nm_mountp)->f_mntfromname);
			error = nfs_sndlock(rep);
			if (!error) {
				error = nfs_reconnect(rep);
				if (!error)
					goto tryagain;
				nfs_sndunlock(rep);
			}
		}
	} else {
		/*
		 * We could have failed while rebinding the datagram socket
		 * so we need to attempt to rebind here.
		 */
		if ((so = rep->r_nmp->nm_so) == NULL) {
			error = nfs_sndlock(rep);
			if (!error) {
				error = nfs_reconnect(rep);
				nfs_sndunlock(rep);
			}
			if (error)
				return (error);
			if (!rep->r_nmp) /* if unmounted then bailout */
				return (ENXIO);
			so = rep->r_nmp->nm_so;
		}
		bzero(&msg, sizeof(msg));
		len = 0;
		do {
			rcvlen = 1000000;
			error = sock_receivembuf(so, &msg, mp, 0, &rcvlen);
			if (!rep->r_nmp) /* if unmounted then bailout */
				goto shutout;
			if (error) {
				error2 = nfs_sigintr(rep->r_nmp, rep, p);
				if (error2) {
					error = error2;
					goto shutout;
				}
			}
			/* Reconnect for all errors.  We may be receiving
			 * soft/hard/blocking errors because of a network
			 * change.
			 * XXX: we should rate limit or delay this
			 * to once every N attempts or something.
			 * although TCP doesn't seem to.
			 */
			if (error) {
				error2 = nfs_sndlock(rep);
				if (!error2) {
					error2 = nfs_reconnect(rep);
					if (error2)
						error = error2;
					else if (!rep->r_nmp) /* if unmounted then bailout */
						error = ENXIO;
					else
						so = rep->r_nmp->nm_so;
					nfs_sndunlock(rep);
				} else {
					error = error2;
				}
			}
		} while (error == EWOULDBLOCK);
	}
shutout:
	if (error) {
		mbuf_freem(*mp);
		*mp = NULL;
	}
	return (error);
}

/*
 * Implement receipt of reply on a socket.
 * We must search through the list of received datagrams matching them
 * with outstanding requests using the xid, until ours is found.
 */
/* ARGSUSED */
int
nfs_reply(myrep)
	struct nfsreq *myrep;
{
	struct nfsreq *rep;
	struct nfsmount *nmp = myrep->r_nmp;
	long t1;
	mbuf_t mrep, md;
	u_long rxid, *tl;
	caddr_t dpos, cp2;
	int error;

	/*
	 * Loop around until we get our own reply
	 */
	for (;;) {
		/*
		 * Lock against other receivers so that I don't get stuck in
		 * sbwait() after someone else has received my reply for me.
		 * Also necessary for connection based protocols to avoid
		 * race conditions during a reconnect.
		 * If nfs_rcvlock() returns EALREADY, that means that
		 * the reply has already been recieved by another
		 * process and we can return immediately.  In this
		 * case, the lock is not taken to avoid races with
		 * other processes.
		 */
		error = nfs_rcvlock(myrep);
		if (error == EALREADY)
			return (0);
		if (error)
			return (error);
		
		/*
		 * If we slept after putting bits otw, then reply may have
		 * arrived.  In which case returning is required, or we
		 * would hang trying to nfs_receive an already received reply.
		 */
		if (myrep->r_mrep != NULL) {
			nfs_rcvunlock(myrep);
			FSDBG(530, myrep->r_xid, myrep, myrep->r_nmp, -1);
			return (0);
		}
		/*
		 * Get the next Rpc reply off the socket. Assume myrep->r_nmp
		 * is still intact by checks done in nfs_rcvlock.
		 */
		error = nfs_receive(myrep, &mrep);
		/*
		 * Bailout asap if nfsmount struct gone (unmounted). 
		 */
		if (!myrep->r_nmp) {
			FSDBG(530, myrep->r_xid, myrep, nmp, -2);
			if (mrep)
				mbuf_freem(mrep);
			return (ENXIO);
		}
		if (error) {
			FSDBG(530, myrep->r_xid, myrep, nmp, error);
			nfs_rcvunlock(myrep);

			/* Bailout asap if nfsmount struct gone (unmounted). */
			if (!myrep->r_nmp) {
				if (mrep)
					mbuf_freem(mrep);
				return (ENXIO);
			}

			/*
			 * Ignore routing errors on connectionless protocols??
			 */
			if (NFSIGNORE_SOERROR(nmp->nm_sotype, error)) {
				if (nmp->nm_so) {
					int clearerror;
					int optlen = sizeof(clearerror);
					sock_getsockopt(nmp->nm_so, SOL_SOCKET, SO_ERROR, &clearerror, &optlen);
				}
				continue;
			}
			if (mrep)
				mbuf_freem(mrep);
			return (error);
		}

		/*
		 * We assume all is fine, but if we did not have an error
                 * and mrep is 0, better not dereference it. nfs_receive
                 * calls soreceive which carefully sets error=0 when it got
                 * errors on sbwait (tsleep). In most cases, I assume that's 
                 * so we could go back again. In tcp case, EPIPE is returned.
                 * In udp, case nfs_receive gets back here with no error and no
                 * mrep. Is the right fix to have soreceive check for process
                 * aborted after sbwait and return something non-zero? Should
                 * nfs_receive give an EPIPE?  Too risky to play with those
                 * two this late in game for a shutdown problem. Instead,
                 * just check here and get out. (ekn)
		 */
		if (!mrep) {
			nfs_rcvunlock(myrep);
                        FSDBG(530, myrep->r_xid, myrep, nmp, -3);
                        return (ENXIO); /* sounds good */
                }
                        
		/*
		 * Get the xid and check that it is an rpc reply
		 */
		md = mrep;
		dpos = mbuf_data(md);
		nfsm_dissect(tl, u_long *, 2*NFSX_UNSIGNED);
		rxid = *tl++;
		if (*tl != rpc_reply) {
			OSAddAtomic(1, (SInt32*)&nfsstats.rpcinvalid);
			mbuf_freem(mrep);
nfsmout:
			if (nmp->nm_state & NFSSTA_RCVLOCK)
				nfs_rcvunlock(myrep);
			continue;
		}

		/*
		 * Loop through the request list to match up the reply
		 * Iff no match, just drop the datagram
		 */
		TAILQ_FOREACH(rep, &nfs_reqq, r_chain) {
			if (rep->r_mrep == NULL && rxid == rep->r_xid) {
				/* Found it.. */
				rep->r_mrep = mrep;
				rep->r_md = md;
				rep->r_dpos = dpos;
				/*
				 * If we're tracking the round trip time
				 * then we update the circular log here
				 * with the stats from our current request.
				 */
				if (nfsrtton) {
					struct rttl *rt;

					rt = &nfsrtt.rttl[nfsrtt.pos];
					rt->proc = rep->r_procnum;
					rt->rto = NFS_RTO(nmp, proct[rep->r_procnum]);
					rt->sent = nmp->nm_sent;
					rt->cwnd = nmp->nm_cwnd;
					if (proct[rep->r_procnum] == 0)
						panic("nfs_reply: proct[%d] is zero", rep->r_procnum);
					rt->srtt = nmp->nm_srtt[proct[rep->r_procnum] - 1];
					rt->sdrtt = nmp->nm_sdrtt[proct[rep->r_procnum] - 1];
					rt->fsid = vfs_statfs(nmp->nm_mountp)->f_fsid;
					microtime(&rt->tstamp); // XXX unused
					if (rep->r_flags & R_TIMING)
						rt->rtt = rep->r_rtt;
					else
						rt->rtt = 1000000;
					nfsrtt.pos = (nfsrtt.pos + 1) % NFSRTTLOGSIZ;
				}
				/*
				 * Update congestion window.
				 * Do the additive increase of
				 * one rpc/rtt.
				 */
				FSDBG(530, rep->r_xid, rep, nmp->nm_sent,
				      nmp->nm_cwnd);
				if (nmp->nm_cwnd <= nmp->nm_sent) {
					nmp->nm_cwnd +=
					   (NFS_CWNDSCALE * NFS_CWNDSCALE +
					   (nmp->nm_cwnd >> 1)) / nmp->nm_cwnd;
					if (nmp->nm_cwnd > NFS_MAXCWND)
						nmp->nm_cwnd = NFS_MAXCWND;
				}
                                if (rep->r_flags & R_SENT) {
                                    rep->r_flags &= ~R_SENT;
                                    nmp->nm_sent -= NFS_CWNDSCALE;
                               }
				/*
				 * Update rtt using a gain of 0.125 on the mean
				 * and a gain of 0.25 on the deviation.
				 */
				if (rep->r_flags & R_TIMING) {
					/*
					 * Since the timer resolution of
					 * NFS_HZ is so course, it can often
					 * result in r_rtt == 0. Since
					 * r_rtt == N means that the actual
					 * rtt is between N+dt and N+2-dt ticks,
					 * add 1.
					 */
					if (proct[rep->r_procnum] == 0)
						panic("nfs_reply: proct[%d] is zero", rep->r_procnum);
					t1 = rep->r_rtt + 1;
					t1 -= (NFS_SRTT(rep) >> 3);
					NFS_SRTT(rep) += t1;
					if (t1 < 0)
						t1 = -t1;
					t1 -= (NFS_SDRTT(rep) >> 2);
					NFS_SDRTT(rep) += t1;
				}
				nmp->nm_timeouts = 0;
				break;
			}
		}
		nfs_rcvunlock(myrep);
		/*
		 * If not matched to a request, drop it.
		 * If it's mine, get out.
		 */
		if (rep == 0) {
			OSAddAtomic(1, (SInt32*)&nfsstats.rpcunexpected);
			mbuf_freem(mrep);
		} else if (rep == myrep) {
			if (rep->r_mrep == NULL)
				panic("nfs_reply: nil r_mrep");
			return (0);
		}
		FSDBG(530, myrep->r_xid, myrep, rep,
		      rep ? rep->r_xid : myrep->r_flags);
	}
}

/*
 * nfs_request - goes something like this
 *	- fill in request struct
 *	- links it into list
 *	- calls nfs_send() for first transmit
 *	- calls nfs_receive() to get reply
 *	- break down rpc header and return with nfs reply pointed to
 *	  by mrep or error
 * nb: always frees up mreq mbuf list
 */
int
nfs_request(vp, mp, mrest, procnum, procp, cred, mrp, mdp, dposp, xidp)
	vnode_t vp;
	mount_t mp;
	mbuf_t mrest;
	int procnum;
	proc_t procp;
	kauth_cred_t cred;
	mbuf_t *mrp;
	mbuf_t *mdp;
	caddr_t *dposp;
	u_int64_t *xidp;
{
	mbuf_t m, mrep, m2;
	struct nfsreq re, *rep;
	u_long *tl;
	int i;
	struct nfsmount *nmp;
	mbuf_t md, mheadend;
	char nickv[RPCX_NICKVERF];
	time_t waituntil;
	caddr_t dpos, cp2;
	int t1, error = 0, mrest_len, auth_len, auth_type;
	int trylater_delay = NFS_TRYLATERDEL, failed_auth = 0;
	int verf_len, verf_type;
	u_long xid;
	char *auth_str, *verf_str;
	NFSKERBKEY_T key;		/* save session key */
	int nmsotype;
	struct timeval now;

	if (mrp)
		*mrp = NULL;
	if (xidp)
		*xidp = 0;
	nmp = VFSTONFS(mp);

	rep = &re;

	if (vp)
		nmp = VFSTONFS(vnode_mount(vp));
	if (nmp == NULL ||
	    (nmp->nm_state & (NFSSTA_FORCE|NFSSTA_TIMEO)) ==
	    (NFSSTA_FORCE|NFSSTA_TIMEO)) {
		mbuf_freem(mrest);
		return (ENXIO);
	}
	nmsotype = nmp->nm_sotype;

	FSDBG_TOP(531, vp, procnum, nmp, rep);

	rep->r_nmp = nmp;
	rep->r_vp = vp;
	rep->r_procp = procp;
	rep->r_procnum = procnum;
	microuptime(&now);
	rep->r_lastmsg = now.tv_sec -
	    ((nmp->nm_tprintf_delay) - (nmp->nm_tprintf_initial_delay));
	i = 0;
	m = mrest;
	while (m) {
		i += mbuf_len(m);
		m = mbuf_next(m);
	}
	mrest_len = i;

	/*
	 * Get the RPC header with authorization.
	 */
kerbauth:
	nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;
	if (!nmp) {
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		mbuf_freem(mrest);
		return (ENXIO);
	}
	verf_str = auth_str = (char *)0;
	if (nmp->nm_flag & NFSMNT_KERB) {
		verf_str = nickv;
		verf_len = sizeof (nickv);
		auth_type = RPCAUTH_KERB4;
		bzero((caddr_t)key, sizeof (key));
		if (failed_auth || nfs_getnickauth(nmp, cred, &auth_str,
			&auth_len, verf_str, verf_len)) {
			nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;
			if (!nmp) {
				FSDBG_BOT(531, 2, vp, error, rep);
				mbuf_freem(mrest);
				return (ENXIO);
			}
			error = nfs_getauth(nmp, rep, cred, &auth_str,
				&auth_len, verf_str, &verf_len, key);
			nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;
			if (!error && !nmp)
				error = ENXIO;
			if (error) {
				FSDBG_BOT(531, 2, vp, error, rep);
				mbuf_freem(mrest);
				return (error);
			}
		}
	} else {
		auth_type = RPCAUTH_UNIX;
		if (cred->cr_ngroups < 1)
			panic("nfsreq nogrps");
		auth_len = ((((cred->cr_ngroups - 1) > nmp->nm_numgrps) ?
			nmp->nm_numgrps : (cred->cr_ngroups - 1)) << 2) +
			5 * NFSX_UNSIGNED;
	}
	error = nfsm_rpchead(cred, nmp->nm_flag, procnum, auth_type, auth_len,
	     auth_str, verf_len, verf_str, mrest, mrest_len, &mheadend, &xid, &m);
	if (auth_str)
		_FREE(auth_str, M_TEMP);
	if (error) {
		mbuf_freem(mrest);
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		return (error);
	}
	if (xidp)
		*xidp = ntohl(xid) + ((u_int64_t)nfs_xidwrap << 32);

	/*
	 * For stream protocols, insert a Sun RPC Record Mark.
	 */
	if (nmsotype == SOCK_STREAM) {
		error = mbuf_prepend(&m, NFSX_UNSIGNED, MBUF_WAITOK);
		if (error) {
			mbuf_freem(m);
			FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
			return (error);
		}
		*((u_long*)mbuf_data(m)) =
			htonl(0x80000000 | (mbuf_pkthdr_len(m) - NFSX_UNSIGNED));
	}
	rep->r_mreq = m;
	rep->r_xid = xid;
tryagain:
	nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;
	if (nmp && (nmp->nm_flag & NFSMNT_SOFT))
		rep->r_retry = nmp->nm_retry;
	else
		rep->r_retry = NFS_MAXREXMIT + 1;	/* past clip limit */
	rep->r_rtt = rep->r_rexmit = 0;
	if (proct[procnum] > 0)
		rep->r_flags = R_TIMING;
	else
		rep->r_flags = 0;
	rep->r_mrep = NULL;

	/*
	 * Do the client side RPC.
	 */
	OSAddAtomic(1, (SInt32*)&nfsstats.rpcrequests);
	/*
	 * Chain request into list of outstanding requests. Be sure
	 * to put it LAST so timer finds oldest requests first.
	 */
	TAILQ_INSERT_TAIL(&nfs_reqq, rep, r_chain);

	/*
	 * If backing off another request or avoiding congestion, don't
	 * send this one now but let timer do it. If not timing a request,
	 * do it now.
	 */
	if (nmp && nmp->nm_so && (nmp->nm_sotype != SOCK_DGRAM ||
			   (nmp->nm_flag & NFSMNT_DUMBTIMR) ||
			   nmp->nm_sent < nmp->nm_cwnd)) {
		int connrequired = (nmp->nm_sotype == SOCK_STREAM);

		if (connrequired)
			error = nfs_sndlock(rep);

		/*
		 * Set the R_SENT before doing the send in case another thread
		 * processes the reply before the nfs_send returns here
		 */
		if (!error) {
			if ((rep->r_flags & R_MUSTRESEND) == 0) {
				FSDBG(531, rep->r_xid, rep, nmp->nm_sent,
				      nmp->nm_cwnd);
				nmp->nm_sent += NFS_CWNDSCALE;
				rep->r_flags |= R_SENT;
			}

			error = mbuf_copym(m, 0, MBUF_COPYALL, MBUF_WAITOK, &m2);
			if (!error)
				error = nfs_send(nmp->nm_so, nmp->nm_nam, m2, rep);
			if (connrequired)
				nfs_sndunlock(rep);
		}
		nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;
		if (error) {
			if (nmp)
				nmp->nm_sent -= NFS_CWNDSCALE;
			rep->r_flags &= ~R_SENT;
		}
	} else {
		rep->r_rtt = -1;
	}

	/*
	 * Wait for the reply from our send or the timer's.
	 */
	if (!error || error == EPIPE)
		error = nfs_reply(rep);

	/*
	 * RPC done, unlink the request.
	 */
	nfs_repdequeue(rep);

	nmp = vp ? VFSTONFS(vnode_mount(vp)) : rep->r_nmp;

	/*
	 * Decrement the outstanding request count.
	 */
	if (rep->r_flags & R_SENT) {
		rep->r_flags &= ~R_SENT;	/* paranoia */
		if (nmp) {
			FSDBG(531, rep->r_xid, rep, nmp->nm_sent, nmp->nm_cwnd);
			nmp->nm_sent -= NFS_CWNDSCALE;
		}
	}

	/*
	 * If there was a successful reply and a tprintf msg.
	 * tprintf a response.
	 */
	if (!error)
		nfs_up(nmp, procp, NFSSTA_TIMEO,
			(rep->r_flags & R_TPRINTFMSG) ? "is alive again" : NULL);
	mrep = rep->r_mrep;
	md = rep->r_md;
	dpos = rep->r_dpos;
	if (!error && !nmp)
		error = ENXIO;
	if (error) {
		mbuf_freem(rep->r_mreq);
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		return (error);
	}

	/*
	 * break down the rpc header and check if ok
	 */
	nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
	if (*tl++ == rpc_msgdenied) {
		if (*tl == rpc_mismatch)
			error = EOPNOTSUPP;
		else if ((nmp->nm_flag & NFSMNT_KERB) && *tl++ == rpc_autherr) {
			if (!failed_auth) {
				failed_auth++;
				error = mbuf_setnext(mheadend, NULL);
				mbuf_freem(mrep);
				mbuf_freem(rep->r_mreq);
				if (!error)
					goto kerbauth;
				printf("nfs_request: mbuf_setnext failed\n");
			} else
				error = EAUTH;
		} else
			error = EACCES;
		mbuf_freem(mrep);
		mbuf_freem(rep->r_mreq);
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		return (error);
	}

	/*
	 * Grab any Kerberos verifier, otherwise just throw it away.
	 */
	verf_type = fxdr_unsigned(int, *tl++);
	i = fxdr_unsigned(int, *tl);
	if ((nmp->nm_flag & NFSMNT_KERB) && verf_type == RPCAUTH_KERB4) {
		error = nfs_savenickauth(nmp, cred, i, key, &md, &dpos, mrep);
		if (error)
			goto nfsmout;
	} else if (i > 0)
		nfsm_adv(nfsm_rndup(i));
	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	/* 0 == ok */
	if (*tl == 0) {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		if (*tl != 0) {
			error = fxdr_unsigned(int, *tl);
			if ((nmp->nm_flag & NFSMNT_NFSV3) &&
				error == NFSERR_TRYLATER) {
				mbuf_freem(mrep);
				error = 0;
				microuptime(&now);
				waituntil = now.tv_sec + trylater_delay;
				while (now.tv_sec < waituntil) {
					tsleep((caddr_t)&lbolt, PSOCK, "nfstrylater", 0);
					microuptime(&now);
				}
				trylater_delay *= 2;
				if (trylater_delay > 60)
					trylater_delay = 60;
				goto tryagain;
			}

			/*
			 * If the File Handle was stale, invalidate the
			 * lookup cache, just in case.
			 */
			if ((error == ESTALE) && vp)
				cache_purge(vp);
			if (nmp->nm_flag & NFSMNT_NFSV3) {
				*mrp = mrep;
				*mdp = md;
				*dposp = dpos;
				error |= NFSERR_RETERR;
			} else {
				mbuf_freem(mrep);
				error &= ~NFSERR_RETERR;
			}
			mbuf_freem(rep->r_mreq);
			FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
			return (error);
		}

		*mrp = mrep;
		*mdp = md;
		*dposp = dpos;
		mbuf_freem(rep->r_mreq);
		FSDBG_BOT(531, 0xf0f0f0f0, rep->r_xid, nmp, rep);
		return (0);
	}
	mbuf_freem(mrep);
	error = EPROTONOSUPPORT;
nfsmout:
	mbuf_freem(rep->r_mreq);
	FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
	return (error);
}

#ifndef NFS_NOSERVER
/*
 * Generate the rpc reply header
 * siz arg. is used to decide if adding a cluster is worthwhile
 */
int
nfs_rephead(siz, nd, slp, err, mrq, mbp, bposp)
	int siz;
	struct nfsrv_descript *nd;
	struct nfssvc_sock *slp;
	int err;
	mbuf_t *mrq;
	mbuf_t *mbp;
	caddr_t *bposp;
{
	u_long *tl;
	mbuf_t mreq;
	caddr_t bpos;
	mbuf_t mb, mb2;
	int error, mlen;

	/*
	 * If this is a big reply, use a cluster else
	 * try and leave leading space for the lower level headers.
	 */
	siz += RPC_REPLYSIZ;
	if (siz >= nfs_mbuf_minclsize) {
		error = mbuf_getpacket(MBUF_WAITOK, &mreq);
	} else {
		error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &mreq);
	}
	if (error) {
		/* unable to allocate packet */
		/* XXX nfsstat? */
		return (error);
	}
	mb = mreq;
	tl = mbuf_data(mreq);
	mlen = 6 * NFSX_UNSIGNED;
	if (siz < nfs_mbuf_minclsize) {
		/* leave space for lower level headers */
		tl += 80/sizeof(*tl);  /* XXX max_hdr? XXX */
		mbuf_setdata(mreq, tl, mlen);
	} else {
		mbuf_setlen(mreq, mlen);
	}
	bpos = ((caddr_t)tl) + mlen;
	*tl++ = txdr_unsigned(nd->nd_retxid);
	*tl++ = rpc_reply;
	if (err == ERPCMISMATCH || (err & NFSERR_AUTHERR)) {
		*tl++ = rpc_msgdenied;
		if (err & NFSERR_AUTHERR) {
			*tl++ = rpc_autherr;
			*tl = txdr_unsigned(err & ~NFSERR_AUTHERR);
			mlen -= NFSX_UNSIGNED;
			mbuf_setlen(mreq, mlen);
			bpos -= NFSX_UNSIGNED;
		} else {
			*tl++ = rpc_mismatch;
			*tl++ = txdr_unsigned(RPC_VER2);
			*tl = txdr_unsigned(RPC_VER2);
		}
	} else {
		*tl++ = rpc_msgaccepted;

		/*
		 * For Kerberos authentication, we must send the nickname
		 * verifier back, otherwise just RPCAUTH_NULL.
		 */
		if (nd->nd_flag & ND_KERBFULL) {
		    struct nfsuid *nuidp;
		    struct timeval ktvin, ktvout;
		    uid_t uid = kauth_cred_getuid(nd->nd_cr);

		    lck_rw_lock_shared(&slp->ns_rwlock);
		    for (nuidp = NUIDHASH(slp, uid)->lh_first;
			nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
			if (kauth_cred_getuid(nuidp->nu_cr) == uid &&
			    (!nd->nd_nam2 || netaddr_match(NU_NETFAM(nuidp),
			     &nuidp->nu_haddr, nd->nd_nam2)))
			    break;
		    }
		    if (nuidp) {
			ktvin.tv_sec =
			    txdr_unsigned(nuidp->nu_timestamp.tv_sec - 1);
			ktvin.tv_usec =
			    txdr_unsigned(nuidp->nu_timestamp.tv_usec);

			/*
			 * Encrypt the timestamp in ecb mode using the
			 * session key.
			 */
#if NFSKERB
			XXX
#endif

			*tl++ = rpc_auth_kerb;
			*tl++ = txdr_unsigned(3 * NFSX_UNSIGNED);
			*tl = ktvout.tv_sec;
			nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
			*tl++ = ktvout.tv_usec;
			*tl++ = txdr_unsigned(kauth_cred_getuid(nuidp->nu_cr));
		    } else {
			*tl++ = 0;
			*tl++ = 0;
		    }
		    lck_rw_done(&slp->ns_rwlock);
		} else {
			*tl++ = 0;
			*tl++ = 0;
		}
		switch (err) {
		case EPROGUNAVAIL:
			*tl = txdr_unsigned(RPC_PROGUNAVAIL);
			break;
		case EPROGMISMATCH:
			*tl = txdr_unsigned(RPC_PROGMISMATCH);
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			// XXX hard coded versions
			*tl++ = txdr_unsigned(2);
			*tl = txdr_unsigned(3);
			break;
		case EPROCUNAVAIL:
			*tl = txdr_unsigned(RPC_PROCUNAVAIL);
			break;
		case EBADRPC:
			*tl = txdr_unsigned(RPC_GARBAGE);
			break;
		default:
			*tl = 0;
			if (err != NFSERR_RETVOID) {
				nfsm_build(tl, u_long *, NFSX_UNSIGNED);
				if (err)
				    *tl = txdr_unsigned(nfsrv_errmap(nd, err));
				else
				    *tl = 0;
			}
			break;
		}
	}

	if (mrq != NULL)
		*mrq = mreq;
	*mbp = mb;
	*bposp = bpos;
	if (err != 0 && err != NFSERR_RETVOID) {
		OSAddAtomic(1, (SInt32*)&nfsstats.srvrpc_errs);
	}
	return (0);
}


#endif /* NFS_NOSERVER */


/*
 * From FreeBSD 1.58, a Matt Dillon fix...
 * Flag a request as being about to terminate.
 * The nm_sent count is decremented now to avoid deadlocks when the process
 * in soreceive() hasn't yet managed to send its own request.
 */
static void
nfs_softterm(struct nfsreq *rep)
{

	rep->r_flags |= R_SOFTTERM;
	if (rep->r_flags & R_SENT) {
		FSDBG(532, rep->r_xid, rep, rep->r_nmp->nm_sent,
		      rep->r_nmp->nm_cwnd);
		rep->r_nmp->nm_sent -= NFS_CWNDSCALE;
		rep->r_flags &= ~R_SENT;
	}
}

void
nfs_timer_funnel(void * arg)
{
	(void) thread_funnel_set(kernel_flock, TRUE);
	nfs_timer(arg);
	(void) thread_funnel_set(kernel_flock, FALSE);

}

/*
 * Ensure rep isn't in use by the timer, then dequeue it.
 */
static void
nfs_repdequeue(struct nfsreq *rep)
{

	while ((rep->r_flags & R_BUSY)) {
		rep->r_flags |= R_WAITING;
		tsleep(rep, PSOCK, "repdeq", 0);
	}
	TAILQ_REMOVE(&nfs_reqq, rep, r_chain);
}

/*
 * Busy (lock) a nfsreq, used by the nfs timer to make sure it's not
 * free()'d out from under it.
 */
static void
nfs_repbusy(struct nfsreq *rep)
{

	if ((rep->r_flags & R_BUSY))
		panic("rep locked");
	rep->r_flags |= R_BUSY;
}

/*
 * Unbusy the nfsreq passed in, return the next nfsreq in the chain busied.
 */
static struct nfsreq *
nfs_repnext(struct nfsreq *rep)
{
	struct nfsreq * nextrep;

	if (rep == NULL)
		return (NULL);
	/*
	 * We need to get and busy the next req before signalling the
	 * current one, otherwise wakeup() may block us and we'll race to
	 * grab the next req.
	 */
	nextrep = TAILQ_NEXT(rep, r_chain);
	if (nextrep != NULL)
		nfs_repbusy(nextrep);
	/* unbusy and signal. */
	rep->r_flags &= ~R_BUSY;
	if ((rep->r_flags & R_WAITING)) {
		rep->r_flags &= ~R_WAITING;
		wakeup(rep);
	}
	return (nextrep);
}

/*
 * Nfs timer routine
 * Scan the nfsreq list and retranmit any requests that have timed out
 * To avoid retransmission attempts on STREAM sockets (in the future) make
 * sure to set the r_retry field to 0 (implies nm_retry == 0).
 */
void
nfs_timer(__unused void *arg)
{
	struct nfsreq *rep;
	mbuf_t m;
	socket_t so;
	struct nfsmount *nmp;
	int timeo;
	int error;
#ifndef NFS_NOSERVER
	struct nfssvc_sock *slp;
	u_quad_t cur_usec;
#endif /* NFS_NOSERVER */
	int flags, rexmit, cwnd, sent;
	u_long xid;
	struct timeval now;

	rep = TAILQ_FIRST(&nfs_reqq);
	if (rep != NULL)
		nfs_repbusy(rep);
	microuptime(&now);
	for ( ; rep != NULL ; rep = nfs_repnext(rep)) {
		nmp = rep->r_nmp;
		if (!nmp) /* unmounted */
		    continue;
		if (rep->r_mrep || (rep->r_flags & R_SOFTTERM))
			continue;
		if (nfs_sigintr(nmp, rep, rep->r_procp))
			continue;
		if (nmp->nm_tprintf_initial_delay != 0 &&
		    (rep->r_rexmit > 2 || (rep->r_flags & R_RESENDERR)) &&
		    rep->r_lastmsg + nmp->nm_tprintf_delay < now.tv_sec) {
			rep->r_lastmsg = now.tv_sec;
			nfs_down(rep->r_nmp, rep->r_procp, 0, NFSSTA_TIMEO,
				"not responding");
			rep->r_flags |= R_TPRINTFMSG;
			if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
				/* we're not yet completely mounted and */
				/* we can't complete an RPC, so we fail */
				OSAddAtomic(1, (SInt32*)&nfsstats.rpctimeouts);
				nfs_softterm(rep);
				continue;
			}
		}
		if (rep->r_rtt >= 0) {
			rep->r_rtt++;
			if (nmp->nm_flag & NFSMNT_DUMBTIMR)
				timeo = nmp->nm_timeo;
			else
				timeo = NFS_RTO(nmp, proct[rep->r_procnum]);
			/* ensure 62.5 ms floor */
			while (16 * timeo < hz)
			    timeo *= 2;
			if (nmp->nm_timeouts > 0)
				timeo *= nfs_backoff[nmp->nm_timeouts - 1];
			if (rep->r_rtt <= timeo)
				continue;
			if (nmp->nm_timeouts < 8)
				nmp->nm_timeouts++;
		}
		/*
		 * Check for too many retransmits.  This is never true for
		 * 'hard' mounts because we set r_retry to NFS_MAXREXMIT + 1
		 * and never allow r_rexmit to be more than NFS_MAXREXMIT.
		 */
		if (rep->r_rexmit >= rep->r_retry) {	/* too many */
			OSAddAtomic(1, (SInt32*)&nfsstats.rpctimeouts);
			nfs_softterm(rep);
			continue;
		}
		if (nmp->nm_sotype != SOCK_DGRAM) {
			if (++rep->r_rexmit > NFS_MAXREXMIT)
				rep->r_rexmit = NFS_MAXREXMIT;
			continue;
		}
		if ((so = nmp->nm_so) == NULL)
			continue;

		/*
		 * If there is enough space and the window allows..
		 *	Resend it
		 * Set r_rtt to -1 in case we fail to send it now.
		 */
		rep->r_rtt = -1;
		if (((nmp->nm_flag & NFSMNT_DUMBTIMR) ||
		    (rep->r_flags & R_SENT) ||
		    nmp->nm_sent < nmp->nm_cwnd) &&
		   (mbuf_copym(rep->r_mreq, 0, MBUF_COPYALL, MBUF_DONTWAIT, &m) == 0)){
			struct msghdr	msg;
			/*
			 * Iff first send, start timing
			 * else turn timing off, backoff timer
			 * and divide congestion window by 2.
			 * We update these *before* the send to avoid
			 * racing against receiving the reply.
			 * We save them so we can restore them on send error.
			 */
			flags = rep->r_flags;
			rexmit = rep->r_rexmit;
			cwnd = nmp->nm_cwnd;
			sent = nmp->nm_sent;
			xid = rep->r_xid;
			if (rep->r_flags & R_SENT) {
				rep->r_flags &= ~R_TIMING;
				if (++rep->r_rexmit > NFS_MAXREXMIT)
					rep->r_rexmit = NFS_MAXREXMIT;
				nmp->nm_cwnd >>= 1;
				if (nmp->nm_cwnd < NFS_CWNDSCALE)
					nmp->nm_cwnd = NFS_CWNDSCALE;
				OSAddAtomic(1, (SInt32*)&nfsstats.rpcretries);
			} else {
				rep->r_flags |= R_SENT;
				nmp->nm_sent += NFS_CWNDSCALE;
			}
			FSDBG(535, xid, rep, nmp->nm_sent, nmp->nm_cwnd);

	 		bzero(&msg, sizeof(msg));
			if ((nmp->nm_flag & NFSMNT_NOCONN) == NFSMNT_NOCONN) {
				msg.msg_name = mbuf_data(nmp->nm_nam);
				msg.msg_namelen = mbuf_len(nmp->nm_nam);
			}
			error = sock_sendmbuf(so, &msg, m, MSG_DONTWAIT, NULL);

			FSDBG(535, xid, error, sent, cwnd);

			if (error) {
				if (error == EWOULDBLOCK) {
					rep->r_flags = flags;
					rep->r_rexmit = rexmit;
					nmp->nm_cwnd = cwnd;
					nmp->nm_sent = sent;
					rep->r_xid = xid;
				}
				else {
					if (NFSIGNORE_SOERROR(nmp->nm_sotype, error)) {
						int clearerror;
						int optlen = sizeof(clearerror);
						sock_getsockopt(nmp->nm_so, SOL_SOCKET, SO_ERROR, &clearerror, &optlen);
					}
					rep->r_flags  = flags | R_RESENDERR;
					rep->r_rexmit = rexmit;
					nmp->nm_cwnd = cwnd;
					nmp->nm_sent = sent;
					if (flags & R_SENT)
						OSAddAtomic(-1, (SInt32*)&nfsstats.rpcretries);
				}
			} else
				rep->r_rtt = 0;
		}
	}
	microuptime(&now);
#ifndef NFS_NOSERVER
	/*
	 * Scan the write gathering queues for writes that need to be
	 * completed now.
	 */
	cur_usec = (u_quad_t)now.tv_sec * 1000000 + (u_quad_t)now.tv_usec;
	lck_mtx_lock(nfsd_mutex);
	TAILQ_FOREACH(slp, &nfssvc_sockhead, ns_chain) {
	    if (slp->ns_wgtime && (slp->ns_wgtime <= cur_usec))
		nfsrv_wakenfsd(slp);
	}
	while ((slp = TAILQ_FIRST(&nfssvc_deadsockhead))) {
		if ((slp->ns_timestamp + 5) > now.tv_sec)
			break;
		TAILQ_REMOVE(&nfssvc_deadsockhead, slp, ns_chain);
		nfsrv_slpfree(slp);
	}
	lck_mtx_unlock(nfsd_mutex);
#endif /* NFS_NOSERVER */

	if (nfsbuffreeuptimestamp + 30 <= now.tv_sec) {
		/*
		 * We haven't called nfs_buf_freeup() in a little while.
		 * So, see if we can free up any stale/unused bufs now.
		 */
		nfs_buf_freeup(1);
	}

	timeout(nfs_timer_funnel, (void *)0, nfs_ticks);

}


/*
 * Test for a termination condition pending on the process.
 * This is used to determine if we need to bail on a mount.
 * EIO is returned if there has been a soft timeout.
 * EINTR is returned if there is a signal pending that is not being ignored
 * and the mount is interruptable, or if we are a thread that is in the process
 * of cancellation (also SIGKILL posted).
 */
int
nfs_sigintr(nmp, rep, p)
	struct nfsmount *nmp;
	struct nfsreq *rep;
	proc_t p;
{
	sigset_t pending_sigs;
	int context_good = 0;
	struct nfsmount *repnmp;
	extern proc_t kernproc;

	if (nmp == NULL)
		return (ENXIO);
	if (rep != NULL) {
		repnmp = rep->r_nmp;
		/* we've had a forced unmount. */
		if (repnmp == NULL)
			return (ENXIO);
		/* request has timed out on a 'soft' mount. */
		if (rep->r_flags & R_SOFTTERM)
			return (EIO);
		/*
		 * We're in the progress of a force unmount and there's
		 * been a timeout we're dead and fail IO.
		 */
		if ((repnmp->nm_state & (NFSSTA_FORCE|NFSSTA_TIMEO)) ==
		   (NFSSTA_FORCE|NFSSTA_TIMEO))
			return (EIO);
		/* Someone is unmounting us, go soft and mark it. */
		if (repnmp->nm_mountp->mnt_kern_flag & MNTK_FRCUNMOUNT) {
			repnmp->nm_flag |= NFSMNT_SOFT;
			nmp->nm_state |= NFSSTA_FORCE;
		}
		/*
		 * If the mount is hung and we've requested not to hang
		 * on remote filesystems, then bail now.
		 */
		if (p != NULL && (proc_noremotehang(p)) != 0 &&
		    (repnmp->nm_state & NFSSTA_TIMEO) != 0)
			return (EIO);
	}
	/* XXX: is this valid?  this probably should be an assertion. */
	if (p == NULL)
		return (0);

	/* Is this thread belongs to kernel task; then abort check  is not needed */
	if ((current_proc() != kernproc) && current_thread_aborted()) {
		return (EINTR);
	}
	/* mask off thread and process blocked signals. */

	pending_sigs = proc_pendingsignals(p, NFSINT_SIGMASK);
	if (pending_sigs && (nmp->nm_flag & NFSMNT_INT) != 0)
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
nfs_sndlock(rep)
	struct nfsreq *rep;
{
	int *statep;
	proc_t p;
	int error, slpflag = 0, slptimeo = 0;

	if (rep->r_nmp == NULL)
		return (ENXIO);
	statep = &rep->r_nmp->nm_state;

	p = rep->r_procp;
	if (rep->r_nmp->nm_flag & NFSMNT_INT)
		slpflag = PCATCH;
	while (*statep & NFSSTA_SNDLOCK) {
		error = nfs_sigintr(rep->r_nmp, rep, p);
		if (error)
			return (error);
		*statep |= NFSSTA_WANTSND;
		if (p != NULL && (proc_noremotehang(p)) != 0)
			slptimeo = hz;
		tsleep((caddr_t)statep, slpflag | (PZERO - 1), "nfsndlck", slptimeo);
		if (slpflag == PCATCH) {
			slpflag = 0;
			slptimeo = 2 * hz;
		}
		/*
		 * Make sure while we slept that the mountpoint didn't go away.
		 * nfs_sigintr and callers expect it in tact.
		 */
		if (!rep->r_nmp) 
			return (ENXIO); /* don't have lock until out of loop */
	}
	*statep |= NFSSTA_SNDLOCK;
	return (0);
}

/*
 * Unlock the stream socket for others.
 */
void
nfs_sndunlock(rep)
	struct nfsreq *rep;
{
	int *statep;

	if (rep->r_nmp == NULL)
		return;
	statep = &rep->r_nmp->nm_state;
	if ((*statep & NFSSTA_SNDLOCK) == 0)
		panic("nfs sndunlock");
	*statep &= ~NFSSTA_SNDLOCK;
	if (*statep & NFSSTA_WANTSND) {
		*statep &= ~NFSSTA_WANTSND;
		wakeup((caddr_t)statep);
	}
}

static int
nfs_rcvlock(struct nfsreq *rep)
{
	int *statep;
	int error, slpflag, slptimeo = 0;

	/* make sure we still have our mountpoint */
	if (!rep->r_nmp) {
		if (rep->r_mrep != NULL)
			return (EALREADY);
		return (ENXIO);
	}

	statep = &rep->r_nmp->nm_state;
	FSDBG_TOP(534, rep->r_xid, rep, rep->r_nmp, *statep);
	if (rep->r_nmp->nm_flag & NFSMNT_INT)
		slpflag = PCATCH;
	else
		slpflag = 0;
	while (*statep & NFSSTA_RCVLOCK) {
		if ((error = nfs_sigintr(rep->r_nmp, rep, rep->r_procp))) {
			FSDBG_BOT(534, rep->r_xid, rep, rep->r_nmp, 0x100);
			return (error);
		} else if (rep->r_mrep != NULL) {
			/*
			 * Don't bother sleeping if reply already arrived
			 */
			FSDBG_BOT(534, rep->r_xid, rep, rep->r_nmp, 0x101);
			return (EALREADY);
		}
		FSDBG(534, rep->r_xid, rep, rep->r_nmp, 0x102);
		*statep |= NFSSTA_WANTRCV;
		/*
		 * We need to poll if we're P_NOREMOTEHANG so that we
		 * call nfs_sigintr periodically above.
		 */
		if (rep->r_procp != NULL &&
		    (proc_noremotehang(rep->r_procp)) != 0)
			slptimeo = hz;
		tsleep((caddr_t)statep, slpflag | (PZERO - 1), "nfsrcvlk", slptimeo);
		if (slpflag == PCATCH) {
			slpflag = 0;
			slptimeo = 2 * hz;
		}
		/*
		 * Make sure while we slept that the mountpoint didn't go away.
		 * nfs_sigintr and caller nfs_reply expect it intact.
		 */
		if (!rep->r_nmp)  {
			FSDBG_BOT(534, rep->r_xid, rep, rep->r_nmp, 0x103);
			return (ENXIO); /* don't have lock until out of loop */
		}
	}
	/*
	 * nfs_reply will handle it if reply already arrived.
	 * (We may have slept or been preempted).
	 */
	FSDBG_BOT(534, rep->r_xid, rep, rep->r_nmp, *statep);
	*statep |= NFSSTA_RCVLOCK;
	return (0);
}

/*
 * Unlock the stream socket for others.
 */
static void
nfs_rcvunlock(struct nfsreq *rep)
{
	int *statep;
	
	if (rep->r_nmp == NULL)
		return;
	statep = &rep->r_nmp->nm_state;

	FSDBG(533, statep, *statep, 0, 0);
	if ((*statep & NFSSTA_RCVLOCK) == 0)
		panic("nfs rcvunlock");
	*statep &= ~NFSSTA_RCVLOCK;
	if (*statep & NFSSTA_WANTRCV) {
		*statep &= ~NFSSTA_WANTRCV;
		wakeup((caddr_t)statep);
	}
}


#ifndef NFS_NOSERVER
/*
 * Socket upcall routine for the nfsd sockets.
 * The caddr_t arg is a pointer to the "struct nfssvc_sock".
 * Essentially do as much as possible non-blocking, else punt and it will
 * be called with MBUF_WAITOK from an nfsd.
 */
void
nfsrv_rcv(socket_t so, caddr_t arg, int waitflag)
{
	struct nfssvc_sock *slp = (struct nfssvc_sock *)arg;

	if (!nfs_numnfsd || !(slp->ns_flag & SLP_VALID))
		return;

	lck_rw_lock_exclusive(&slp->ns_rwlock);
	nfsrv_rcv_locked(so, slp, waitflag);
	/* Note: ns_rwlock gets dropped when called with MBUF_DONTWAIT */
}
void
nfsrv_rcv_locked(socket_t so, struct nfssvc_sock *slp, int waitflag)
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
				ns_flag = SLP_NEEDQ;
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
				else
					slp->ns_rec = m;
				slp->ns_recend = m;
				mbuf_setnextpkt(m, NULL);
			}
#if 0
			if (error) {
				/*
				 * This may be needed in the future to support
				 * non-byte-stream connection-oriented protocols
				 * such as SCTP.
				 */
				/*
				 * This (slp->ns_sotype == SOCK_STREAM) should really
				 * be a check for PR_CONNREQUIRED.
				 */
				if ((slp->ns_sotype == SOCK_STREAM)
					&& error != EWOULDBLOCK) {
					ns_flag = SLP_DISCONN;
					goto dorecs;
				}
			}
#endif
		} while (mp);
	}

	/*
	 * Now try and process the request records, non-blocking.
	 */
dorecs:
	if (ns_flag)
		slp->ns_flag |= ns_flag;
	if (waitflag == MBUF_DONTWAIT) {
		int wake = (slp->ns_rec || (slp->ns_flag & (SLP_NEEDQ | SLP_DISCONN)));
		lck_rw_done(&slp->ns_rwlock);
		if (wake && nfs_numnfsd) {
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
nfsrv_getstream(slp, waitflag)
	struct nfssvc_sock *slp;
	int waitflag;
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
		else
		    slp->ns_rec = slp->ns_frag;
		slp->ns_recend = slp->ns_frag;
		slp->ns_frag = NULL;
	    }
	}
}

/*
 * Parse an RPC header.
 */
int
nfsrv_dorec(slp, nfsd, ndp)
	struct nfssvc_sock *slp;
	struct nfsd *nfsd;
	struct nfsrv_descript **ndp;
{
	mbuf_t m;
	mbuf_t nam;
	struct nfsrv_descript *nd;
	int error;

	*ndp = NULL;
	if ((slp->ns_flag & SLP_VALID) == 0 || (slp->ns_rec == NULL))
		return (ENOBUFS);
	MALLOC_ZONE(nd, struct nfsrv_descript *,
			sizeof (struct nfsrv_descript), M_NFSRVDESC, M_WAITOK);
	if (!nd)
		return (ENOMEM);
	m = slp->ns_rec;
	slp->ns_rec = mbuf_nextpkt(m);
	if (slp->ns_rec)
		mbuf_setnextpkt(m, NULL);
	else
		slp->ns_recend = NULL;
	if (mbuf_type(m) == MBUF_TYPE_SONAME) {
		nam = m;
		m = mbuf_next(m);
		if ((error = mbuf_setnext(nam, NULL)))
			panic("nfsrv_dorec: mbuf_setnext failed %d\n", error);
	} else
		nam = NULL;
	nd->nd_md = nd->nd_mrep = m;
	nd->nd_nam2 = nam;
	nd->nd_dpos = mbuf_data(m);
	error = nfs_getreq(nd, nfsd, TRUE);
	if (error) {
		if (nam)
			mbuf_freem(nam);
		FREE_ZONE((caddr_t)nd,	sizeof *nd, M_NFSRVDESC);
		return (error);
	}
	*ndp = nd;
	nfsd->nfsd_nd = nd;
	return (0);
}

/*
 * Parse an RPC request
 * - verify it
 * - fill in the cred struct.
 */
int
nfs_getreq(nd, nfsd, has_header)
	struct nfsrv_descript *nd;
	struct nfsd *nfsd;
	int has_header;
{
	int len, i;
	u_long *tl;
	long t1;
	uio_t uiop;
	caddr_t dpos, cp2, cp;
	u_long nfsvers, auth_type;
	uid_t nickuid;
	int error = 0, ticklen;
	mbuf_t mrep, md;
	struct nfsuid *nuidp;
	uid_t user_id;
	gid_t group_id;
	int ngroups;
	struct ucred temp_cred;
	struct timeval tvin, tvout, now;
	char uio_buf[ UIO_SIZEOF(1) ];
#if 0				/* until encrypted keys are implemented */
	NFSKERBKEYSCHED_T keys;	/* stores key schedule */
#endif

	nd->nd_cr = NULL;

	mrep = nd->nd_mrep;
	md = nd->nd_md;
	dpos = nd->nd_dpos;
	if (has_header) {
		nfsm_dissect(tl, u_long *, 10 * NFSX_UNSIGNED);
		nd->nd_retxid = fxdr_unsigned(u_long, *tl++);
		if (*tl++ != rpc_call) {
			mbuf_freem(mrep);
			return (EBADRPC);
		}
	} else
		nfsm_dissect(tl, u_long *, 8 * NFSX_UNSIGNED);
	nd->nd_repstat = 0;
	nd->nd_flag = 0;
	if (*tl++ != rpc_vers) {
		nd->nd_repstat = ERPCMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	if (*tl != nfs_prog) {
		nd->nd_repstat = EPROGUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	tl++;
	nfsvers = fxdr_unsigned(u_long, *tl++);
	if ((nfsvers < NFS_VER2) || (nfsvers > NFS_VER3)) {
		nd->nd_repstat = EPROGMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	else if (nfsvers == NFS_VER3)
		nd->nd_flag = ND_NFSV3;
	nd->nd_procnum = fxdr_unsigned(u_long, *tl++);
	if (nd->nd_procnum == NFSPROC_NULL)
		return (0);
	if ((nd->nd_procnum >= NFS_NPROCS) ||
		(!nd->nd_flag && nd->nd_procnum > NFSV2PROC_STATFS)) {
		nd->nd_repstat = EPROCUNAVAIL;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	if ((nd->nd_flag & ND_NFSV3) == 0)
		nd->nd_procnum = nfsv3_procid[nd->nd_procnum];
	auth_type = *tl++;
	len = fxdr_unsigned(int, *tl++);
	if (len < 0 || len > RPCAUTH_MAXSIZ) {
		mbuf_freem(mrep);
		return (EBADRPC);
	}

	nd->nd_flag &= ~ND_KERBAUTH;
	/*
	 * Handle auth_unix or auth_kerb.
	 */
	if (auth_type == rpc_auth_unix) {
		len = fxdr_unsigned(int, *++tl);
		if (len < 0 || len > NFS_MAXNAMLEN) {
			mbuf_freem(mrep);
			return (EBADRPC);
		}
		bzero(&temp_cred, sizeof(temp_cred));
		nfsm_adv(nfsm_rndup(len));
		nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
		user_id = fxdr_unsigned(uid_t, *tl++);
		group_id = fxdr_unsigned(gid_t, *tl++);
		temp_cred.cr_groups[0] = group_id;
		len = fxdr_unsigned(int, *tl);
		if (len < 0 || len > RPCAUTH_UNIXGIDS) {
			mbuf_freem(mrep);
			return (EBADRPC);
		}
		nfsm_dissect(tl, u_long *, (len + 2) * NFSX_UNSIGNED);
		for (i = 1; i <= len; i++)
		    if (i < NGROUPS)
			temp_cred.cr_groups[i] = fxdr_unsigned(gid_t, *tl++);
		    else
			tl++;
		ngroups = (len >= NGROUPS) ? NGROUPS : (len + 1);
		if (ngroups > 1)
		    nfsrvw_sort(&temp_cred.cr_groups[0], ngroups);
		len = fxdr_unsigned(int, *++tl);
		if (len < 0 || len > RPCAUTH_MAXSIZ) {
			mbuf_freem(mrep);
			return (EBADRPC);
		}
		temp_cred.cr_uid = user_id;
		temp_cred.cr_ngroups = ngroups;
		nd->nd_cr = kauth_cred_create(&temp_cred); 
		if (nd->nd_cr == NULL) {
			nd->nd_repstat = ENOMEM;
			nd->nd_procnum = NFSPROC_NOOP;
			return (0);
		}
		if (len > 0)
			nfsm_adv(nfsm_rndup(len));
	} else if (auth_type == rpc_auth_kerb) {
		switch (fxdr_unsigned(int, *tl++)) {
		case RPCAKN_FULLNAME:
			ticklen = fxdr_unsigned(int, *tl);
			*((u_long *)nfsd->nfsd_authstr) = *tl;
			uiop = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
						&uio_buf[0], sizeof(uio_buf));
			if (!uiop) {
				nd->nd_repstat = ENOMEM;
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}

			// LP64todo - fix this
			nfsd->nfsd_authlen = (nfsm_rndup(ticklen) + (NFSX_UNSIGNED * 2));
			if ((nfsm_rndup(ticklen) + NFSX_UNSIGNED) > (len - 2 * NFSX_UNSIGNED)) {
				mbuf_freem(mrep);
				return (EBADRPC);
			}
			uio_addiov(uiop, CAST_USER_ADDR_T(&nfsd->nfsd_authstr[4]), RPCAUTH_MAXSIZ - 4);
			// LP64todo - fix this
			nfsm_mtouio(uiop, uio_resid(uiop));
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			if (*tl++ != rpc_auth_kerb ||
				fxdr_unsigned(int, *tl) != 4 * NFSX_UNSIGNED) {
				printf("Bad kerb verifier\n");
				nd->nd_repstat = (NFSERR_AUTHERR|AUTH_BADVERF);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			nfsm_dissect(cp, caddr_t, 4 * NFSX_UNSIGNED);
			tl = (u_long *)cp;
			if (fxdr_unsigned(int, *tl) != RPCAKN_FULLNAME) {
				printf("Not fullname kerb verifier\n");
				nd->nd_repstat = (NFSERR_AUTHERR|AUTH_BADVERF);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			cp += NFSX_UNSIGNED;
			bcopy(cp, nfsd->nfsd_verfstr, 3 * NFSX_UNSIGNED);
			nfsd->nfsd_verflen = 3 * NFSX_UNSIGNED;
			nd->nd_flag |= ND_KERBFULL;
			nfsd->nfsd_flag |= NFSD_NEEDAUTH;
			break;
		case RPCAKN_NICKNAME:
			if (len != 2 * NFSX_UNSIGNED) {
				printf("Kerb nickname short\n");
				nd->nd_repstat = (NFSERR_AUTHERR|AUTH_BADCRED);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			nickuid = fxdr_unsigned(uid_t, *tl);
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			if (*tl++ != rpc_auth_kerb ||
				fxdr_unsigned(int, *tl) != 3 * NFSX_UNSIGNED) {
				printf("Kerb nick verifier bad\n");
				nd->nd_repstat = (NFSERR_AUTHERR|AUTH_BADVERF);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
			tvin.tv_sec = *tl++;
			tvin.tv_usec = *tl;

			for (nuidp = NUIDHASH(nfsd->nfsd_slp,nickuid)->lh_first;
			    nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
				if (kauth_cred_getuid(nuidp->nu_cr) == nickuid &&
				    (!nd->nd_nam2 ||
				     netaddr_match(NU_NETFAM(nuidp),
				      &nuidp->nu_haddr, nd->nd_nam2)))
					break;
			}
			if (!nuidp) {
				nd->nd_repstat =
					(NFSERR_AUTHERR|AUTH_REJECTCRED);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}

			/*
			 * Now, decrypt the timestamp using the session key
			 * and validate it.
			 */
#if NFSKERB
			XXX
#endif

			tvout.tv_sec = fxdr_unsigned(long, tvout.tv_sec);
			tvout.tv_usec = fxdr_unsigned(long, tvout.tv_usec);
			microtime(&now);
			if (nuidp->nu_expire < now.tv_sec ||
			    nuidp->nu_timestamp.tv_sec > tvout.tv_sec ||
			    (nuidp->nu_timestamp.tv_sec == tvout.tv_sec &&
			     nuidp->nu_timestamp.tv_usec > tvout.tv_usec)) {
				nuidp->nu_expire = 0;
				nd->nd_repstat =
				    (NFSERR_AUTHERR|AUTH_REJECTVERF);
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			bzero(&temp_cred, sizeof(temp_cred));
			ngroups = nuidp->nu_cr->cr_ngroups;
			for (i = 0; i < ngroups; i++)
				temp_cred.cr_groups[i] = nuidp->nu_cr->cr_groups[i];
			if (ngroups > 1)
				nfsrvw_sort(&temp_cred.cr_groups[0], ngroups);

			temp_cred.cr_uid = kauth_cred_getuid(nuidp->nu_cr);
			temp_cred.cr_ngroups = ngroups;
			nd->nd_cr = kauth_cred_create(&temp_cred); 
			if (!nd->nd_cr) {
				nd->nd_repstat = ENOMEM;
				nd->nd_procnum = NFSPROC_NOOP;
				return (0);
			}
			nd->nd_flag |= ND_KERBNICK;
		};
	} else {
		nd->nd_repstat = (NFSERR_AUTHERR | AUTH_REJECTCRED);
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}

	nd->nd_md = md;
	nd->nd_dpos = dpos;
	return (0);
nfsmout:
	if (nd->nd_cr)
		kauth_cred_rele(nd->nd_cr);
	return (error);
}

/*
 * Search for a sleeping nfsd and wake it up.
 * SIDE EFFECT: If none found, set NFSD_CHECKSLP flag, so that one of the
 * running nfsds will go look for the work in the nfssvc_sock list.
 * Note: Must be called with nfsd_mutex held.
 */
void
nfsrv_wakenfsd(struct nfssvc_sock *slp)
{
	struct nfsd *nd;

	if ((slp->ns_flag & SLP_VALID) == 0)
		return;

	lck_rw_lock_exclusive(&slp->ns_rwlock);

	if (nfsd_waiting) {
		TAILQ_FOREACH(nd, &nfsd_head, nfsd_chain) {
			if (nd->nfsd_flag & NFSD_WAITING) {
				nd->nfsd_flag &= ~NFSD_WAITING;
				if (nd->nfsd_slp)
					panic("nfsd wakeup");
				slp->ns_sref++;
				nd->nfsd_slp = slp;
				lck_rw_done(&slp->ns_rwlock);
				wakeup((caddr_t)nd);
				return;
			}
		}
	}

	slp->ns_flag |= SLP_DOREC;

	lck_rw_done(&slp->ns_rwlock);

	nfsd_head_flag |= NFSD_CHECKSLP;
}
#endif /* NFS_NOSERVER */

static int
nfs_msg(proc_t p,
	const char *server,
	const char *msg,
	int error)
{
	tpr_t tpr;

	if (p)
		tpr = tprintf_open(p);
	else
		tpr = NULL;
	if (error)
		tprintf(tpr, "nfs server %s: %s, error %d\n", server, msg,
		    error);
	else
		tprintf(tpr, "nfs server %s: %s\n", server, msg);
	tprintf_close(tpr);
	return (0);
}

void
nfs_down(nmp, proc, error, flags, msg)
	struct nfsmount *nmp;
	proc_t proc;
	int error, flags;
	const char *msg;
{
	if (nmp == NULL)
		return;
	if ((flags & NFSSTA_TIMEO) && !(nmp->nm_state & NFSSTA_TIMEO)) {
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESP, 0);
		nmp->nm_state |= NFSSTA_TIMEO;
	}
	if ((flags & NFSSTA_LOCKTIMEO) && !(nmp->nm_state & NFSSTA_LOCKTIMEO)) {
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESPLOCK, 0);
		nmp->nm_state |= NFSSTA_LOCKTIMEO;
	}
	nfs_msg(proc, vfs_statfs(nmp->nm_mountp)->f_mntfromname, msg, error);
}

void
nfs_up(nmp, proc, flags, msg)
	struct nfsmount *nmp;
	proc_t proc;
	int flags;
	const char *msg;
{
	if (nmp == NULL)
		return;
	if (msg)
		nfs_msg(proc, vfs_statfs(nmp->nm_mountp)->f_mntfromname, msg, 0);
	if ((flags & NFSSTA_TIMEO) && (nmp->nm_state & NFSSTA_TIMEO)) {
		nmp->nm_state &= ~NFSSTA_TIMEO;
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESP, 1);
	}
	if ((flags & NFSSTA_LOCKTIMEO) && (nmp->nm_state & NFSSTA_LOCKTIMEO)) {
		nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
		vfs_event_signal(&vfs_statfs(nmp->nm_mountp)->f_fsid, VQ_NOTRESPLOCK, 1);
	}
}

