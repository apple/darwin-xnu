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
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/tprintf.h>
#include <machine/spl.h>

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
#include <nfs/nqnfs.h>

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

#define	TRUE	1
#define	FALSE	0

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
extern u_long nfs_prog, nqnfs_prog;
extern time_t nqnfsstarttime;
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
	0, 1, 0, 2, 1, 3, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0,
	0, 0, 0,
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

static int	nfs_msg __P((struct proc *, const char *, const char *, int));
static int	nfs_rcvlock __P((struct nfsreq *));
static void	nfs_rcvunlock __P((struct nfsreq *));
static int	nfs_receive __P((struct nfsreq *rep, struct mbuf **aname,
				 struct mbuf **mp));
static int	nfs_reconnect __P((struct nfsreq *rep));
static void	nfs_repbusy(struct nfsreq *rep);
static struct nfsreq *	nfs_repnext(struct nfsreq *rep);
static void	nfs_repdequeue(struct nfsreq *rep);

/* XXX */
boolean_t	current_thread_aborted(void);
kern_return_t	thread_terminate(thread_act_t);

#ifndef NFS_NOSERVER 
static int	nfsrv_getstream __P((struct nfssvc_sock *,int));

int (*nfsrv3_procs[NFS_NPROCS]) __P((struct nfsrv_descript *nd,
				    struct nfssvc_sock *slp,
				    struct proc *procp,
				    struct mbuf **mreqp)) = {
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
	nqnfsrv_getlease,
	nqnfsrv_vacated,
	nfsrv_noop,
	nfsrv_noop
};
#endif /* NFS_NOSERVER */

/*
 * NFSTRACE points were changed to FSDBG (KERNEL_DEBUG)
 * But some of this code may prove useful someday...
 */
#undef NFSDIAG
#if NFSDIAG
int nfstraceindx = 0;
struct nfstracerec nfstracebuf[NFSTBUFSIZ] = {{0,0,0,0}};

#define NFSTRACESUSPENDERS
#ifdef NFSTRACESUSPENDERS
uint nfstracemask = 0xfff00200;
int nfstracexid = -1;
uint onfstracemask = 0;
int nfstracesuspend = -1;
#define NFSTRACE_SUSPEND					\
	{							\
	if (nfstracemask) {					\
		onfstracemask = nfstracemask;			\
		nfstracemask = 0;				\
	}							\
	}
#define NFSTRACE_RESUME						\
	{							\
	nfstracesuspend = -1;					\
	if (!nfstracemask)					\
		nfstracemask = onfstracemask;			\
	}
#define NFSTRACE_STARTSUSPENDCOUNTDOWN				\
	{							\
	nfstracesuspend = (nfstraceindx+100) % NFSTBUFSIZ;	\
	}
#define NFSTRACE_SUSPENDING (nfstracesuspend != -1)
#define NFSTRACE_SUSPENSEOVER					\
	(nfstracesuspend > 100 ?				\
		(nfstraceindx >= nfstracesuspend ||		\
		 nfstraceindx < nfstracesuspend - 100) :	\
		(nfstraceindx >= nfstracesuspend &&		\
		 nfstraceindx < nfstracesuspend + 8192 - 100))
#else
uint nfstracemask = 0;
#endif	/* NFSTRACESUSPENDERS */

int nfsprnttimo = 1;

int nfsodata[1024];
int nfsoprocnum, nfsolen;
int nfsbt[32], nfsbtlen;

#if defined(__ppc__)
int
backtrace(int *where, int size)
{
	int register sp, *fp, numsaved;

	__asm__ volatile("mr %0,r1" : "=r" (sp));
	
	fp = (int *)*((int *)sp);
	size /= sizeof(int);
	for (numsaved = 0; numsaved < size; numsaved++) {
		*where++ = fp[2];
		if ((int)fp <= 0)
			break;
		fp = (int *)*fp;
	}
	return (numsaved);
}
#elif defined(__i386__)
int
backtrace()
{
       return (0);  /* Till someone implements a real routine */
}
#else
#error architecture not implemented.
#endif

void
nfsdup(struct nfsreq *rep)
{
	int *ip, i, first = 1, end;
	char *s, b[240];
	struct mbuf *mb;

	if ((nfs_debug & NFS_DEBUG_DUP) == 0)
		return;
	/* last mbuf in chain will be nfs content */
	for (mb = rep->r_mreq; mb->m_next; mb = mb->m_next)
		;
	if (rep->r_procnum == nfsoprocnum && mb->m_len == nfsolen &&
	    !bcmp((caddr_t)nfsodata, mb->m_data, nfsolen)) {
		s = b + sprintf(b, "nfsdup x=%x p=%d h=", rep->r_xid,
				rep->r_procnum);
		end = (int)(VTONFS(rep->r_vp)->n_fhp);
		ip = (int *)(end & ~3);
		end += VTONFS(rep->r_vp)->n_fhsize;
		while ((int)ip < end) {
			i = *ip++;
			if (first) { /* avoid leading zeroes */
				if (i == 0)
					continue;
				first = 0;
				s += sprintf(s, "%x", i);
			} else
				s += sprintf(s, "%08x", i);
		}
		if (first)
			sprintf(s, "%x", 0);
		else /* eliminate trailing zeroes */
			while (*--s == '0')
				*s = 0;
		/*
		 * set a breakpoint here and you can view the
		 * current backtrace and the one saved in nfsbt
		 */
		kprintf("%s\n", b);
	}
	nfsoprocnum = rep->r_procnum;
	nfsolen = mb->m_len;
	bcopy(mb->m_data, (caddr_t)nfsodata, mb->m_len);
	nfsbtlen = backtrace(&nfsbt, sizeof(nfsbt));
}
#endif /* NFSDIAG */


/*
 * attempt to bind a socket to a reserved port
 */
static int
nfs_bind_resv(struct nfsmount *nmp)
{
	struct socket *so = nmp->nm_so;
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

	while (((error = sobind(so, (struct sockaddr *) &sin)) == EADDRINUSE) &&
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
static struct slock nfs_bind_resv_slock;
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
        boolean_t funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);
	nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_RUNNING;

	while (nfs_resv_mounts > 0) {
		simple_lock(&nfs_bind_resv_slock);
		while ((brreq = TAILQ_FIRST(&nfs_bind_resv_request_queue))) {
			TAILQ_REMOVE(&nfs_bind_resv_request_queue, brreq, brr_chain);
			simple_unlock(&nfs_bind_resv_slock);
			brreq->brr_error = nfs_bind_resv(brreq->brr_nmp);
			wakeup(brreq);
			simple_lock(&nfs_bind_resv_slock);
		}
		simple_unlock(&nfs_bind_resv_slock);
		(void)tsleep((caddr_t)&nfs_bind_resv_request_queue, PSOCK,
				"nfs_bind_resv_request_queue", 0);
	}

	nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_INITTED;
	(void) thread_funnel_set(network_flock, funnel_state);
	(void) thread_terminate(current_act());
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
			simple_lock_init(&nfs_bind_resv_slock);
			TAILQ_INIT(&nfs_bind_resv_request_queue);
			nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_INITTED;
		}
		kernel_thread(kernel_task, nfs_bind_resv_thread);
		nfs_bind_resv_thread_state = NFS_BIND_RESV_THREAD_STATE_RUNNING;
	}

	brreq.brr_nmp = nmp;
	brreq.brr_error = 0;

	simple_lock(&nfs_bind_resv_slock);
	TAILQ_INSERT_TAIL(&nfs_bind_resv_request_queue, &brreq, brr_chain);
	simple_unlock(&nfs_bind_resv_slock);

	error = nfs_bind_resv_thread_wake();
	if (error) {
		TAILQ_REMOVE(&nfs_bind_resv_request_queue, &brreq, brr_chain);
		/* Note: we might be able to simply restart the thread */
		return (error);
	}

	(void) tsleep((caddr_t)&brreq, PSOCK, "nfsbindresv", 0);

	return (brreq.brr_error);
}

/*
 * Initialize sockets and congestion for a new NFS connection.
 * We do not free the sockaddr if error.
 */
int
nfs_connect(nmp, rep)
	struct nfsmount *nmp;
	struct nfsreq *rep;
{
	struct socket *so;
	int s, error, rcvreserve, sndreserve;
	struct sockaddr *saddr;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	nmp->nm_so = (struct socket *)0;
	saddr = mtod(nmp->nm_nam, struct sockaddr *);
	error = socreate(saddr->sa_family, &nmp->nm_so, nmp->nm_sotype, 
		nmp->nm_soproto);
	if (error) {
		goto bad;
	}
	so = nmp->nm_so;
	nmp->nm_soflags = so->so_proto->pr_flags;

	/*
	 * Some servers require that the client port be a reserved port number.
	 */
	if (saddr->sa_family == AF_INET && (nmp->nm_flag & NFSMNT_RESVPORT)) {
		struct proc *p;
		/*
		 * sobind() requires current_proc() to have superuser privs.
		 * If this bind is part of a reconnect, and the current proc
		 * doesn't have superuser privs, we hand the sobind() off to
		 * a kernel thread to process.
		 */
		if ((nmp->nm_state & NFSSTA_MOUNTED) &&
		    (p = current_proc()) && suser(p->p_ucred, &p->p_acflag)) {
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
		if (nmp->nm_soflags & PR_CONNREQUIRED) {
			error = ENOTCONN;
			goto bad;
		}
	} else {
		error = soconnect(so, mtod(nmp->nm_nam, struct sockaddr *));
		if (error) {
			goto bad;
		}

		/*
		 * Wait for the connection to complete. Cribbed from the
		 * connect system call but with the wait timing out so
		 * that interruptible mounts don't hang here for a long time.
		 */
		s = splnet();
		while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
			(void) tsleep((caddr_t)&so->so_timeo, PSOCK,
				"nfscon", 2 * hz);
			if ((so->so_state & SS_ISCONNECTING) &&
			    so->so_error == 0 && rep &&
			    (error = nfs_sigintr(nmp, rep, rep->r_procp))) {
				so->so_state &= ~SS_ISCONNECTING;
				splx(s);
				goto bad;
			}
		}
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			splx(s);
			goto bad;
		}
		splx(s);
	}
	/*
	 * Always time out on recieve, this allows us to reconnect the
	 * socket to deal with network changes.
	 */
	so->so_rcv.sb_timeo = (2 * hz);
	if (nmp->nm_flag & (NFSMNT_SOFT | NFSMNT_INT)) {
		so->so_snd.sb_timeo = (5 * hz);
	} else {
		so->so_snd.sb_timeo = 0;
	}
	if (nmp->nm_sotype == SOCK_DGRAM) {
		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR) *
			(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	} else if (nmp->nm_sotype == SOCK_SEQPACKET) {
		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR) *
			(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	} else {
		if (nmp->nm_sotype != SOCK_STREAM)
			panic("nfscon sotype");

		if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
			struct sockopt sopt;
			int val;

			bzero(&sopt, sizeof sopt);
			sopt.sopt_dir = SOPT_SET;
			sopt.sopt_level = SOL_SOCKET;
			sopt.sopt_name = SO_KEEPALIVE;
			sopt.sopt_val = &val;
			sopt.sopt_valsize = sizeof val;
			val = 1;
			sosetopt(so, &sopt);
		}
		if (so->so_proto->pr_protocol == IPPROTO_TCP) {
			struct sockopt sopt;
			int val;

			bzero(&sopt, sizeof sopt);
			sopt.sopt_dir = SOPT_SET;
			sopt.sopt_level = IPPROTO_TCP;
			sopt.sopt_name = TCP_NODELAY;
			sopt.sopt_val = &val;
			sopt.sopt_valsize = sizeof val;
			val = 1;
			sosetopt(so, &sopt);
		}

		sndreserve = (nmp->nm_wsize + NFS_MAXPKTHDR + sizeof (u_long)) * 3;
		rcvreserve = (nmp->nm_rsize + NFS_MAXPKTHDR + sizeof (u_long)) *
				(nmp->nm_readahead > 0 ? nmp->nm_readahead + 1 : 2);
	}

	if (sndreserve > NFS_MAXSOCKBUF)
		sndreserve = NFS_MAXSOCKBUF;
	if (rcvreserve > NFS_MAXSOCKBUF)
		rcvreserve = NFS_MAXSOCKBUF;
	error = soreserve(so, sndreserve, rcvreserve);
	if (error) {
		goto bad;
	}
	so->so_rcv.sb_flags |= SB_NOINTR;
	so->so_snd.sb_flags |= SB_NOINTR;

	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

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
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
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
nfs_reconnect(rep)
	register struct nfsreq *rep;
{
	register struct nfsreq *rp;
	register struct nfsmount *nmp = rep->r_nmp;
	int error;

	nfs_disconnect(nmp);
	while ((error = nfs_connect(nmp, rep))) {
		if (error == EINTR || error == ERESTART)
			return (EINTR);
		if (error == EIO)
			return (EIO);
		nfs_down(rep, rep->r_nmp, rep->r_procp, "can not connect",
			error, NFSSTA_TIMEO);
		if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
			/* we're not yet completely mounted and */
			/* we can't reconnect, so we fail */
			return (error);
		}
		if ((error = nfs_sigintr(rep->r_nmp, rep, rep->r_procp)))
			return (error);
		(void) tsleep((caddr_t)&lbolt, PSOCK, "nfscon", 0);
	}

	NFS_DPF(DUP, ("nfs_reconnect RESEND\n"));
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
nfs_disconnect(nmp)
	register struct nfsmount *nmp;
{
	register struct socket *so;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	if (nmp->nm_so) {
		so = nmp->nm_so;
		nmp->nm_so = (struct socket *)0;
		soshutdown(so, 2);
		soclose(so);
	}
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
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
	register struct socket *so;
	struct mbuf *nam;
	register struct mbuf *top;
	struct nfsreq *rep;
{
	struct sockaddr *sendnam;
	int error, error2, soflags, flags;
	int xidqueued = 0;
	struct nfsreq *rp;
	char savenametolog[MNAMELEN];
	
	if (rep) {
		error = nfs_sigintr(rep->r_nmp, rep, rep->r_procp);
		if (error) {
			m_freem(top);
			return (error);
		}
		if ((so = rep->r_nmp->nm_so) == NULL) {
			rep->r_flags |= R_MUSTRESEND;
			m_freem(top);
			return (0);
		}
		rep->r_flags &= ~R_MUSTRESEND;
		soflags = rep->r_nmp->nm_soflags;
		TAILQ_FOREACH(rp, &nfs_reqq, r_chain)
			if (rp == rep)
				break;
		if (rp)
			xidqueued = rp->r_xid;
	} else
		soflags = so->so_proto->pr_flags;
	if ((soflags & PR_CONNREQUIRED) || (so->so_state & SS_ISCONNECTED) ||
	    (nam == 0))
		sendnam = (struct sockaddr *)0;
	else
		sendnam = mtod(nam, struct sockaddr *);

	if (so->so_type == SOCK_SEQPACKET)
		flags = MSG_EOR;
	else
		flags = 0;

#if NFSDIAG
	if (rep)
		nfsdup(rep);
#endif
	/* 
	 * Save the name here in case mount point goes away when we switch
	 * funnels.  The name is using local stack and is large, but don't
	 * want to block if we malloc.
	 */
	if (rep)
		strncpy(savenametolog,
			rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname,
			MNAMELEN);
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	error = sosend(so, sendnam, (struct uio *)0, top,
		       (struct mbuf *)0, flags);
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

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
				NFS_DPF(DUP,
					("nfs_send RESEND error=%d\n", error));
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
nfs_receive(rep, aname, mp)
	register struct nfsreq *rep;
	struct mbuf **aname;
	struct mbuf **mp;
{
	register struct socket *so;
	struct uio auio;
	struct iovec aio;
	register struct mbuf *m;
	struct mbuf *control;
	u_long len;
	struct sockaddr **getnam;
	struct sockaddr *tmp_nam;
	struct mbuf	*mhck;
	struct sockaddr_in *sin;
	int error, error2, sotype, rcvflg;
	struct proc *p = current_proc();	/* XXX */

	/*
	 * Set up arguments for soreceive()
	 */
	*mp = (struct mbuf *)0;
	*aname = (struct mbuf *)0;
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
			m = m_copym(rep->r_mreq, 0, M_COPYALL, M_WAIT);
			nfsstats.rpcretries++;
			NFS_DPF(DUP,
				("nfs_receive RESEND %s\n",
				rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname));
			error = nfs_send(so, rep->r_nmp->nm_nam, m, rep);
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
			aio.iov_base = (caddr_t) &len;
			aio.iov_len = sizeof(u_long);
			auio.uio_iov = &aio;
			auio.uio_iovcnt = 1;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_READ;
			auio.uio_offset = 0;
			auio.uio_resid = sizeof(u_long);
			auio.uio_procp = p;
			do {
			   rcvflg = MSG_WAITALL;
			   thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			   error = soreceive(so, (struct sockaddr **)0, &auio,
				(struct mbuf **)0, (struct mbuf **)0, &rcvflg);
			   thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			   if (!rep->r_nmp) /* if unmounted then bailout */
				goto shutout;
			   if (error == EWOULDBLOCK && rep) {
				error2 = nfs_sigintr(rep->r_nmp, rep, p);
				if (error2)
					error = error2;
			   }
			} while (error == EWOULDBLOCK);
			if (!error && auio.uio_resid > 0) {
			    log(LOG_INFO,
				 "short receive (%d/%d) from nfs server %s\n",
				 sizeof(u_long) - auio.uio_resid,
				 sizeof(u_long),
				 rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname);
			    error = EPIPE;
			}
			if (error)
				goto errout;
			len = ntohl(len) & ~0x80000000;
			/*
			 * This is SERIOUS! We are out of sync with the sender
			 * and forcing a disconnect/reconnect is all I can do.
			 */
			if (len > NFS_MAXPACKET) {
			    log(LOG_ERR, "%s (%d) from nfs server %s\n",
				"impossible packet length",
				len,
				rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname);
			    error = EFBIG;
			    goto errout;
			}
			auio.uio_resid = len;

			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			do {
			    rcvflg = MSG_WAITALL;
			    error =  soreceive(so, (struct sockaddr **)0,
				&auio, mp, (struct mbuf **)0, &rcvflg);
			    if (!rep->r_nmp) /* if unmounted then bailout */ {
				thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
				goto shutout;
			    }
			} while (error == EWOULDBLOCK || error == EINTR ||
				 error == ERESTART);

			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

			if (!error && auio.uio_resid > 0) {
			    log(LOG_INFO,
				"short receive (%d/%d) from nfs server %s\n",
				len - auio.uio_resid, len,
				rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname);
			    error = EPIPE;
			}
		} else {
			/*
			 * NB: Since uio_resid is big, MSG_WAITALL is ignored
			 * and soreceive() will return when it has either a
			 * control msg or a data msg.
			 * We have no use for control msg., but must grab them
			 * and then throw them away so we know what is going
			 * on.
			 */
			auio.uio_resid = len = 100000000; /* Anything Big */
			auio.uio_procp = p;

			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			do {
			    control = NULL;
			    rcvflg = 0;
			    error =  soreceive(so, (struct sockaddr **)0,
					       &auio, mp, &control, &rcvflg);
			    if (control)
				m_freem(control);
			    if (!rep->r_nmp) /* if unmounted then bailout */ {
				thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
				goto shutout;
 			    }   
			    if (error == EWOULDBLOCK && rep) {
				error2 = nfs_sigintr(rep->r_nmp, rep, p);
				if (error2) {
					thread_funnel_switch(NETWORK_FUNNEL,
					    KERNEL_FUNNEL);
					return (error2);
				}
			    }
			} while (error == EWOULDBLOCK ||
				 (!error && *mp == NULL && control));

			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

			if ((rcvflg & MSG_EOR) == 0)
				printf("Egad!!\n");
			if (!error && *mp == NULL)
				error = EPIPE;
			len -= auio.uio_resid;
		}
errout:
		if (error && error != EINTR && error != ERESTART) {
			m_freem(*mp);
			*mp = (struct mbuf *)0;
			if (error != EPIPE)
				log(LOG_INFO,
				    "receive error %d from nfs server %s\n",
				    error,
				 rep->r_nmp->nm_mountp->mnt_stat.f_mntfromname);
			error = nfs_sndlock(rep);
			if (!error)
				error = nfs_reconnect(rep);
			if (!error)
				goto tryagain;
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
		if (so->so_state & SS_ISCONNECTED)
			getnam = (struct sockaddr **)0;
		else
			getnam = &tmp_nam;;
		auio.uio_resid = len = 1000000;
		auio.uio_procp = p;

		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
		do {
			rcvflg = 0;
			error =  soreceive(so, getnam, &auio, mp,
				(struct mbuf **)0, &rcvflg);

			if ((getnam) && (*getnam)) {
			    MGET(mhck, M_WAIT, MT_SONAME);
			    mhck->m_len = (*getnam)->sa_len;
			    sin = mtod(mhck, struct sockaddr_in *);
			    bcopy(*getnam, sin, sizeof(struct sockaddr_in));
			    mhck->m_hdr.mh_len = sizeof(struct sockaddr_in);
			    FREE(*getnam, M_SONAME);
			    *aname = mhck;
			}
			if (!rep->r_nmp) /* if unmounted then bailout */
				goto dgramout;
			if (error) {
				error2 = nfs_sigintr(rep->r_nmp, rep, p);
				if (error2) {
					error = error2;
					goto dgramout;
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
				thread_funnel_switch(NETWORK_FUNNEL,
				    KERNEL_FUNNEL);
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
				thread_funnel_switch(KERNEL_FUNNEL,
				    NETWORK_FUNNEL);
			}
		} while (error == EWOULDBLOCK);

dgramout:
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		len -= auio.uio_resid;
	}
shutout:
	if (error) {
		m_freem(*mp);
		*mp = (struct mbuf *)0;
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
	register struct nfsreq *rep;
	register struct nfsmount *nmp = myrep->r_nmp;
	register long t1;
	struct mbuf *mrep, *md;
	struct mbuf *nam;
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
		/* XXX why do we ask for nam here? we don't use it! */
		error = nfs_receive(myrep, &nam, &mrep);
		if (nam)
			m_freem(nam);
		/*
		 * Bailout asap if nfsmount struct gone (unmounted). 
		 */
		if (!myrep->r_nmp || !nmp->nm_so) {
			FSDBG(530, myrep->r_xid, myrep, nmp, -2);
			return (ENXIO);
		}
		if (error) {
			FSDBG(530, myrep->r_xid, myrep, nmp, error);
			nfs_rcvunlock(myrep);

			/* Bailout asap if nfsmount struct gone (unmounted). */
			if (!myrep->r_nmp || !nmp->nm_so)
				return (ENXIO);

			/*
			 * Ignore routing errors on connectionless protocols??
			 */
			if (NFSIGNORE_SOERROR(nmp->nm_soflags, error)) {
				nmp->nm_so->so_error = 0;
				if (myrep->r_flags & R_GETONEREP)
					return (0);
				continue;
			}
			return (error);
		}

		/*
		 * We assume all is fine, but if we did not have an error
                 * and mrep is 0, better not dereference it. nfs_receieve
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
                        FSDBG(530, myrep->r_xid, myrep, nmp, -3);
                        return (ENXIO); /* sounds good */
                }
                        
		/*
		 * Get the xid and check that it is an rpc reply
		 */
		md = mrep;
		dpos = mtod(md, caddr_t);
		nfsm_dissect(tl, u_long *, 2*NFSX_UNSIGNED);
		rxid = *tl++;
		if (*tl != rpc_reply) {
#ifndef NFS_NOSERVER
			if (nmp->nm_flag & NFSMNT_NQNFS) {
				if (nqnfs_callback(nmp, mrep, md, dpos))
					nfsstats.rpcinvalid++;
			} else {
				nfsstats.rpcinvalid++;
				m_freem(mrep);
			}
#else
			nfsstats.rpcinvalid++;
			m_freem(mrep);
#endif
nfsmout:
			if (nmp->nm_state & NFSSTA_RCVLOCK)
				nfs_rcvunlock(myrep);
			if (myrep->r_flags & R_GETONEREP)
				return (0); /* this path used by NQNFS */
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
					rt->fsid = nmp->nm_mountp->mnt_stat.f_fsid;
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
			nfsstats.rpcunexpected++;
			m_freem(mrep);
		} else if (rep == myrep) {
			if (rep->r_mrep == NULL)
				panic("nfs_reply: nil r_mrep");
			return (0);
		}
		FSDBG(530, myrep->r_xid, myrep, rep,
		      rep ? rep->r_xid : myrep->r_flags);
		if (myrep->r_flags & R_GETONEREP)
			return (0); /* this path used by NQNFS */
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
nfs_request(vp, mrest, procnum, procp, cred, mrp, mdp, dposp, xidp)
	struct vnode *vp;
	struct mbuf *mrest;
	int procnum;
	struct proc *procp;
	struct ucred *cred;
	struct mbuf **mrp;
	struct mbuf **mdp;
	caddr_t *dposp;
	u_int64_t *xidp;
{
	register struct mbuf *m, *mrep, *m2;
	register struct nfsreq *rep, *rp;
	register u_long *tl;
	register int i;
	struct nfsmount *nmp;
	struct mbuf *md, *mheadend;
	struct nfsnode *np;
	char nickv[RPCX_NICKVERF];
	time_t reqtime, waituntil;
	caddr_t dpos, cp2;
	int t1, nqlflag, cachable, s, error = 0, mrest_len, auth_len, auth_type;
	int trylater_delay = NQ_TRYLATERDEL, trylater_cnt = 0, failed_auth = 0;
	int verf_len, verf_type;
	u_long xid;
	u_quad_t frev;
	char *auth_str, *verf_str;
	NFSKERBKEY_T key;		/* save session key */
	int nmsotype;
	struct timeval now;

	if (mrp)
		*mrp = NULL;
	if (xidp)
		*xidp = 0;

	MALLOC_ZONE(rep, struct nfsreq *,
		    sizeof(struct nfsreq), M_NFSREQ, M_WAITOK);

	nmp = VFSTONFS(vp->v_mount);
	if (nmp == NULL ||
	    (nmp->nm_state & (NFSSTA_FORCE|NFSSTA_TIMEO)) ==
	    (NFSSTA_FORCE|NFSSTA_TIMEO)) {
		FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
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
		i += m->m_len;
		m = m->m_next;
	}
	mrest_len = i;

	/*
	 * Get the RPC header with authorization.
	 */
kerbauth:
	nmp = VFSTONFS(vp->v_mount);
	if (!nmp) {
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
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
			nmp = VFSTONFS(vp->v_mount);
			if (!nmp) {
				FSDBG_BOT(531, 2, vp, error, rep);
				FREE_ZONE((caddr_t)rep,
					sizeof (struct nfsreq), M_NFSREQ);
				m_freem(mrest);
				return (ENXIO);
			}
			error = nfs_getauth(nmp, rep, cred, &auth_str,
				&auth_len, verf_str, &verf_len, key);
			nmp = VFSTONFS(vp->v_mount);
			if (!error && !nmp)
				error = ENXIO;
			if (error) {
				FSDBG_BOT(531, 2, vp, error, rep);
				FREE_ZONE((caddr_t)rep,
					sizeof (struct nfsreq), M_NFSREQ);
				m_freem(mrest);
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
	m = nfsm_rpchead(cred, nmp->nm_flag, procnum, auth_type, auth_len,
	     auth_str, verf_len, verf_str, mrest, mrest_len, &mheadend, &xid);
	if (xidp)
		*xidp = ntohl(xid) + ((u_int64_t)nfs_xidwrap << 32);
	if (auth_str)
		_FREE(auth_str, M_TEMP);

	/*
	 * For stream protocols, insert a Sun RPC Record Mark.
	 */
	if (nmsotype == SOCK_STREAM) {
		M_PREPEND(m, NFSX_UNSIGNED, M_WAIT);
		*mtod(m, u_long *) = htonl(0x80000000 |
					   (m->m_pkthdr.len - NFSX_UNSIGNED));
	}
	rep->r_mreq = m;
	rep->r_xid = xid;
tryagain:
	nmp = VFSTONFS(vp->v_mount);
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
	nfsstats.rpcrequests++;
	/*
	 * Chain request into list of outstanding requests. Be sure
	 * to put it LAST so timer finds oldest requests first.
	 */
	s = splsoftclock();
	TAILQ_INSERT_TAIL(&nfs_reqq, rep, r_chain);

	/* Get send time for nqnfs */
	microtime(&now);
	reqtime = now.tv_sec;

	/*
	 * If backing off another request or avoiding congestion, don't
	 * send this one now but let timer do it. If not timing a request,
	 * do it now.
	 */
	if (nmp && nmp->nm_so && (nmp->nm_sotype != SOCK_DGRAM ||
			   (nmp->nm_flag & NFSMNT_DUMBTIMR) ||
			   nmp->nm_sent < nmp->nm_cwnd)) {
		int connrequired = (nmp->nm_soflags & PR_CONNREQUIRED);

		splx(s);
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

			m2 = m_copym(m, 0, M_COPYALL, M_WAIT);
			error = nfs_send(nmp->nm_so, nmp->nm_nam, m2, rep);
			if (connrequired)
				nfs_sndunlock(rep);
		}
		nmp = VFSTONFS(vp->v_mount);
		if (error) {
			if (nmp)
				nmp->nm_sent -= NFS_CWNDSCALE;
			rep->r_flags &= ~R_SENT;
		}
	} else {
		splx(s);
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

	nmp = VFSTONFS(vp->v_mount);

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
		nfs_up(rep, nmp, procp, "is alive again", NFSSTA_TIMEO);
	mrep = rep->r_mrep;
	md = rep->r_md;
	dpos = rep->r_dpos;
	if (!error && !nmp)
		error = ENXIO;
	if (error) {
		m_freem(rep->r_mreq);
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
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
				mheadend->m_next = (struct mbuf *)0;
				m_freem(mrep);
				m_freem(rep->r_mreq);
				goto kerbauth;
			} else
				error = EAUTH;
		} else
			error = EACCES;
		m_freem(mrep);
		m_freem(rep->r_mreq);
		FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
		FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
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
				m_freem(mrep);
				error = 0;
				microuptime(&now);
				waituntil = now.tv_sec + trylater_delay;
				NFS_DPF(DUP,
					("nfs_request %s flag=%x trylater_cnt=%x waituntil=%lx trylater_delay=%x\n",
					 nmp->nm_mountp->mnt_stat.f_mntfromname,
					 nmp->nm_flag, trylater_cnt, waituntil,
					 trylater_delay));
				while (now.tv_sec < waituntil) {
					(void)tsleep((caddr_t)&lbolt,
						     PSOCK, "nqnfstry", 0);
					microuptime(&now);
				}
				trylater_delay *= 2;
				if (trylater_delay > 60)
					trylater_delay = 60;
				if (trylater_cnt < 7)
					trylater_cnt++;
				goto tryagain;
			}

			/*
			 * If the File Handle was stale, invalidate the
			 * lookup cache, just in case.
			 */
			if (error == ESTALE)
				cache_purge(vp);
			if (nmp->nm_flag & NFSMNT_NFSV3) {
				*mrp = mrep;
				*mdp = md;
				*dposp = dpos;
				error |= NFSERR_RETERR;
			} else {
				m_freem(mrep);
				error &= ~NFSERR_RETERR;
			}
			m_freem(rep->r_mreq);
			FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
			FREE_ZONE((caddr_t)rep,
				   sizeof (struct nfsreq), M_NFSREQ);
			return (error);
		}

		/*
		 * For nqnfs, get any lease in reply
		 */
		if (nmp->nm_flag & NFSMNT_NQNFS) {
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			if (*tl) {
				np = VTONFS(vp);
				nqlflag = fxdr_unsigned(int, *tl);
				nfsm_dissect(tl, u_long *, 4*NFSX_UNSIGNED);
				cachable = fxdr_unsigned(int, *tl++);
				reqtime += fxdr_unsigned(int, *tl++);
				microtime(&now);
				if (reqtime > now.tv_sec) {
				    fxdr_hyper(tl, &frev);
				    nqnfs_clientlease(nmp, np, nqlflag,
						      cachable, reqtime, frev);
				}
			}
		}
		*mrp = mrep;
		*mdp = md;
		*dposp = dpos;
		m_freem(rep->r_mreq);
		FSDBG_BOT(531, 0xf0f0f0f0, rep->r_xid, nmp, rep);
		FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
		return (0);
	}
	m_freem(mrep);
	error = EPROTONOSUPPORT;
nfsmout:
	m_freem(rep->r_mreq);
	FSDBG_BOT(531, error, rep->r_xid, nmp, rep);
	FREE_ZONE((caddr_t)rep, sizeof (struct nfsreq), M_NFSREQ);
	return (error);
}

#ifndef NFS_NOSERVER
/*
 * Generate the rpc reply header
 * siz arg. is used to decide if adding a cluster is worthwhile
 */
int
nfs_rephead(siz, nd, slp, err, cache, frev, mrq, mbp, bposp)
	int siz;
	struct nfsrv_descript *nd;
	struct nfssvc_sock *slp;
	int err;
	int cache;
	u_quad_t *frev;
	struct mbuf **mrq;
	struct mbuf **mbp;
	caddr_t *bposp;
{
	register u_long *tl;
	register struct mbuf *mreq;
	caddr_t bpos;
	struct mbuf *mb, *mb2;

	MGETHDR(mreq, M_WAIT, MT_DATA);
	mb = mreq;
	/*
	 * If this is a big reply, use a cluster else
	 * try and leave leading space for the lower level headers.
	 */
	siz += RPC_REPLYSIZ;
	if (siz >= MINCLSIZE) {
		MCLGET(mreq, M_WAIT);
	} else
		mreq->m_data += max_hdr;
	tl = mtod(mreq, u_long *);
	mreq->m_len = 6 * NFSX_UNSIGNED;
	bpos = ((caddr_t)tl) + mreq->m_len;
	*tl++ = txdr_unsigned(nd->nd_retxid);
	*tl++ = rpc_reply;
	if (err == ERPCMISMATCH || (err & NFSERR_AUTHERR)) {
		*tl++ = rpc_msgdenied;
		if (err & NFSERR_AUTHERR) {
			*tl++ = rpc_autherr;
			*tl = txdr_unsigned(err & ~NFSERR_AUTHERR);
			mreq->m_len -= NFSX_UNSIGNED;
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
		    register struct nfsuid *nuidp;
		    struct timeval ktvin, ktvout;

		    for (nuidp = NUIDHASH(slp, nd->nd_cr.cr_uid)->lh_first;
			nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
			if (nuidp->nu_cr.cr_uid == nd->nd_cr.cr_uid &&
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
			*tl++ = txdr_unsigned(nuidp->nu_cr.cr_uid);
		    } else {
			*tl++ = 0;
			*tl++ = 0;
		    }
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
			if (nd->nd_flag & ND_NQNFS) {
				*tl++ = txdr_unsigned(3);
				*tl = txdr_unsigned(3);
			} else {
				*tl++ = txdr_unsigned(2);
				*tl = txdr_unsigned(3);
			}
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
		};
	}

	/*
	 * For nqnfs, piggyback lease as requested.
	 */
	if ((nd->nd_flag & ND_NQNFS) && err == 0) {
		if (nd->nd_flag & ND_LEASE) {
			nfsm_build(tl, u_long *, 5 * NFSX_UNSIGNED);
			*tl++ = txdr_unsigned(nd->nd_flag & ND_LEASE);
			*tl++ = txdr_unsigned(cache);
			*tl++ = txdr_unsigned(nd->nd_duration);
			txdr_hyper(frev, tl);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = 0;
		}
	}
	if (mrq != NULL)
		*mrq = mreq;
	*mbp = mb;
	*bposp = bpos;
	if (err != 0 && err != NFSERR_RETVOID)
		nfsstats.srvrpc_errs++;
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
nfs_timer_funnel(arg)
	void * arg;
{
	(void) thread_funnel_set(kernel_flock, TRUE);
	nfs_timer(arg);
	(void) thread_funnel_set(kernel_flock, FALSE);

}

/*
 * Ensure rep isn't in use by the timer, then dequeue it.
 */
void
nfs_repdequeue(struct nfsreq *rep)
{
	int s;

	while ((rep->r_flags & R_BUSY)) {
		rep->r_flags |= R_WAITING;
		tsleep(rep, PSOCK, "repdeq", 0);
	}
	s = splsoftclock();
	TAILQ_REMOVE(&nfs_reqq, rep, r_chain);
	splx(s);
}

/*
 * Busy (lock) a nfsreq, used by the nfs timer to make sure it's not
 * free()'d out from under it.
 */
void
nfs_repbusy(struct nfsreq *rep)
{

	if ((rep->r_flags & R_BUSY))
		panic("rep locked");
	rep->r_flags |= R_BUSY;
}

/*
 * Unbusy the nfsreq passed in, return the next nfsreq in the chain busied.
 */
struct nfsreq *
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
nfs_timer(arg)
	void *arg;	/* never used */
{
	register struct nfsreq *rep;
	register struct mbuf *m;
	register struct socket *so;
	register struct nfsmount *nmp;
	register int timeo;
	int s, error;
#ifndef NFS_NOSERVER
	static long lasttime = 0;
	register struct nfssvc_sock *slp;
	u_quad_t cur_usec;
#endif /* NFS_NOSERVER */
#if NFSDIAG
	int rttdiag;
#endif
	int flags, rexmit, cwnd, sent;
	u_long xid;
	struct timeval now;

	s = splnet();
	/*
	 * XXX If preemptable threads are implemented the spls used for the
	 * outstanding request queue must be replaced with mutexes.
	 */
#ifdef NFSTRACESUSPENDERS
	if (NFSTRACE_SUSPENDING) {
		TAILQ_FOREACH(rep, &nfs_reqq, r_chain)
			if (rep->r_xid == nfstracexid)
				break;
		if (!rep) {
			NFSTRACE_RESUME;
		} else if (NFSTRACE_SUSPENSEOVER) {
			NFSTRACE_SUSPEND;
		}
	}
#endif
	rep = TAILQ_FIRST(&nfs_reqq);
	if (rep != NULL)
		nfs_repbusy(rep);
	microuptime(&now);
	for ( ; rep != NULL ; rep = nfs_repnext(rep)) {
#ifdef NFSTRACESUSPENDERS
		if (rep->r_mrep && !NFSTRACE_SUSPENDING) {
			nfstracexid = rep->r_xid;
			NFSTRACE_STARTSUSPENDCOUNTDOWN;
		}
#endif
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
			nfs_down(rep, rep->r_nmp, rep->r_procp, "not responding",
				0, NFSSTA_TIMEO);
			if (!(nmp->nm_state & NFSSTA_MOUNTED)) {
				/* we're not yet completely mounted and */
				/* we can't complete an RPC, so we fail */
				nfsstats.rpctimeouts++;
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
			nfsstats.rpctimeouts++;
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
#if NFSDIAG
		rttdiag = rep->r_rtt;
#endif
		rep->r_rtt = -1;
		if (sbspace(&so->so_snd) >= rep->r_mreq->m_pkthdr.len &&
		   ((nmp->nm_flag & NFSMNT_DUMBTIMR) ||
		    (rep->r_flags & R_SENT) ||
		    nmp->nm_sent < nmp->nm_cwnd) &&
		   (m = m_copym(rep->r_mreq, 0, M_COPYALL, M_DONTWAIT))){

	 		struct proc *p = current_proc();

#if NFSDIAG
			if (rep->r_flags & R_SENT && nfsprnttimo &&
			    nmp->nm_timeouts >= nfsprnttimo) {
				int t = proct[rep->r_procnum];
				if (t)
					NFS_DPF(DUP, ("nfs_timer %s nmtm=%d tms=%d rtt=%d tm=%d p=%d A=%d D=%d\n", nmp->nm_mountp->mnt_stat.f_mntfromname, nmp->nm_timeo, nmp->nm_timeouts, rttdiag, timeo, rep->r_procnum, nmp->nm_srtt[t-1], nmp->nm_sdrtt[t-1]));
				else
					NFS_DPF(DUP, ("nfs_timer %s nmtm=%d tms=%d rtt=%d tm=%d p=%d\n", nmp->nm_mountp->mnt_stat.f_mntfromname, nmp->nm_timeo, nmp->nm_timeouts, rttdiag, timeo, rep->r_procnum));
			}
			nfsdup(rep);
#endif /* NFSDIAG */
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
				nfsstats.rpcretries++;
			} else {
				rep->r_flags |= R_SENT;
				nmp->nm_sent += NFS_CWNDSCALE;
			}
			FSDBG(535, xid, rep, nmp->nm_sent, nmp->nm_cwnd);

			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);

			if ((nmp->nm_flag & NFSMNT_NOCONN) == 0)
			    error = (*so->so_proto->pr_usrreqs->pru_send)
				(so, 0, m, 0, 0, p);
			else
			    error = (*so->so_proto->pr_usrreqs->pru_send)
				(so, 0, m, mtod(nmp->nm_nam, struct sockaddr *), 0, p);

			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

			FSDBG(535, xid, error, sent, cwnd);

			if (error) {
				if (NFSIGNORE_SOERROR(nmp->nm_soflags, error))
					so->so_error = 0;
				rep->r_flags  = flags | R_RESENDERR;
				rep->r_rexmit = rexmit;
				nmp->nm_cwnd = cwnd;
				nmp->nm_sent = sent;
				if (flags & R_SENT)
					nfsstats.rpcretries--;
			} else
				rep->r_rtt = 0;
		}
	}
	microuptime(&now);
#ifndef NFS_NOSERVER
	/*
	 * Call the nqnfs server timer once a second to handle leases.
	 */
	if (lasttime != now.tv_sec) {
		lasttime = now.tv_sec;
		nqnfs_serverd();
	}

	/*
	 * Scan the write gathering queues for writes that need to be
	 * completed now.
	 */
	cur_usec = (u_quad_t)now.tv_sec * 1000000 + (u_quad_t)now.tv_usec;
	TAILQ_FOREACH(slp, &nfssvc_sockhead, ns_chain) {
	    if (LIST_FIRST(&slp->ns_tq) &&
		LIST_FIRST(&slp->ns_tq)->nd_time <= cur_usec)
		nfsrv_wakenfsd(slp);
	}
#endif /* NFS_NOSERVER */
	splx(s);

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
	struct proc *p;
{
	struct uthread *curr_td;
	sigset_t pending_sigs;
	int context_good = 0;
	struct nfsmount *repnmp;

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
		if ((repnmp->nm_mountp->mnt_kern_flag & MNTK_FRCUNMOUNT)) {
			repnmp->nm_flag |= NFSMNT_SOFT;
			nmp->nm_state |= NFSSTA_FORCE;
		}
		/*
		 * If the mount is hung and we've requested not to hang
		 * on remote filesystems, then bail now.
		 */
		if (p != NULL && (p->p_flag & P_NOREMOTEHANG) != 0 &&
		    (repnmp->nm_state & NFSSTA_TIMEO) != 0)
			return (EIO);
	}
	/* XXX: is this valid?  this probably should be an assertion. */
	if (p == NULL)
		return (0);

	/*
	 * XXX: Since nfs doesn't have a good shot at getting the current
	 * thread we take a guess.  (only struct proc * are passed to VOPs)
	 * What we do is look at the current thread, if it belongs to the
	 * passed in proc pointer then we have a "good/accurate" context
	 * and can make an accurate guess as to what to do.
	 * However if we have a bad context we have to make due with what
	 * is in the proc struct which may not be as up to date as we'd
	 * like.
	 * This is ok because the process will call us with the correct
	 * context after a short timeout while waiting for a response.
	 */
	curr_td = (struct uthread *)get_bsdthread_info(current_act());
	if (curr_td->uu_proc == p)
		context_good = 1;
	if (context_good && current_thread_aborted())
		return (EINTR);
	/* mask off thread and process blocked signals. */
	if (context_good)
		pending_sigs = curr_td->uu_siglist & ~curr_td->uu_sigmask;
	else
		pending_sigs = p->p_siglist;
	/* mask off process level and NFS ignored signals. */
	pending_sigs &= ~p->p_sigignore & NFSINT_SIGMASK;
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
	register int *statep;
	struct proc *p;
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
		if (p != NULL && (p->p_flag & P_NOREMOTEHANG) != 0)
			slptimeo = hz;
		(void) tsleep((caddr_t)statep, slpflag | (PZERO - 1),
			"nfsndlck", slptimeo);
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
	register int *statep;

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
nfs_rcvlock(rep)
	register struct nfsreq *rep;
{
	register int *statep;
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
		    (rep->r_procp->p_flag & P_NOREMOTEHANG) != 0)
			slptimeo = hz;
		(void) tsleep((caddr_t)statep, slpflag | (PZERO - 1),
			      "nfsrcvlk", slptimeo);
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
	 * (We may have slept or been preempted while on network funnel).
	 */
	FSDBG_BOT(534, rep->r_xid, rep, rep->r_nmp, *statep);
	*statep |= NFSSTA_RCVLOCK;
	return (0);
}

/*
 * Unlock the stream socket for others.
 */
static void
nfs_rcvunlock(rep)
	register struct nfsreq *rep;
{
	register int *statep;
	
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
 * be called with M_WAIT from an nfsd.
 */
 /* 
 * Needs to run under network funnel 
 */
void
nfsrv_rcv(so, arg, waitflag)
	struct socket *so;
	caddr_t arg;
	int waitflag;
{
	register struct nfssvc_sock *slp = (struct nfssvc_sock *)arg;
	register struct mbuf *m;
	struct mbuf *mp, *mhck;
	struct sockaddr *nam;
	struct uio auio;
	int flags, ns_nflag=0, error;
	struct sockaddr_in  *sin;

	if ((slp->ns_flag & SLP_VALID) == 0)
		return;
#ifdef notdef
	/*
	 * Define this to test for nfsds handling this under heavy load.
	 */
	if (waitflag == M_DONTWAIT) {
		ns_nflag = SLPN_NEEDQ;
		goto dorecs;
	}
#endif
	auio.uio_procp = NULL;
	if (so->so_type == SOCK_STREAM) {
		/*
		 * If there are already records on the queue, defer soreceive()
		 * to an nfsd so that there is feedback to the TCP layer that
		 * the nfs servers are heavily loaded.
		 */
		if (slp->ns_rec && waitflag == M_DONTWAIT) {
			ns_nflag = SLPN_NEEDQ;
			goto dorecs;
		}

		/*
		 * Do soreceive().
		 */
		auio.uio_resid = 1000000000;
		flags = MSG_DONTWAIT;
		error = soreceive(so, (struct sockaddr **) 0, &auio, &mp, (struct mbuf **)0, &flags);
		if (error || mp == (struct mbuf *)0) {
			if (error == EWOULDBLOCK)
				ns_nflag = SLPN_NEEDQ;
			else
				ns_nflag = SLPN_DISCONN;
			goto dorecs;
		}
		m = mp;
		if (slp->ns_rawend) {
			slp->ns_rawend->m_next = m;
			slp->ns_cc += 1000000000 - auio.uio_resid;
		} else {
			slp->ns_raw = m;
			slp->ns_cc = 1000000000 - auio.uio_resid;
		}
		while (m->m_next)
			m = m->m_next;
		slp->ns_rawend = m;

		/*
		 * Now try and parse record(s) out of the raw stream data.
		 */
		error = nfsrv_getstream(slp, waitflag);
		if (error) {
			if (error == EPERM)
				ns_nflag = SLPN_DISCONN;
			else
				ns_nflag = SLPN_NEEDQ;
		}
	} else {
		do {
			auio.uio_resid = 1000000000;
			flags = MSG_DONTWAIT | MSG_NEEDSA;
			nam = 0;
			mp = 0;
			error = soreceive(so, &nam, &auio, &mp,
						(struct mbuf **)0, &flags);
			
			if (mp) {
				if (nam) {
					MGET(mhck, M_WAIT, MT_SONAME);
					mhck->m_len = nam->sa_len;
					sin = mtod(mhck, struct sockaddr_in *);
					bcopy(nam, sin, sizeof(struct sockaddr_in));
					mhck->m_hdr.mh_len = sizeof(struct sockaddr_in);

					m = mhck;
					m->m_next = mp;
				} else
					m = mp;
				if (slp->ns_recend)
					slp->ns_recend->m_nextpkt = m;
				else
					slp->ns_rec = m;
				slp->ns_recend = m;
				m->m_nextpkt = (struct mbuf *)0;
			}
			if (nam) {
				FREE(nam, M_SONAME);
			}
			if (error) {
				if ((so->so_proto->pr_flags & PR_CONNREQUIRED)
					&& error != EWOULDBLOCK) {
					ns_nflag = SLPN_DISCONN;
					goto dorecs;
				}
			}
		} while (mp);
	}

	/*
	 * Now try and process the request records, non-blocking.
	 */
dorecs:
	if (ns_nflag)
		slp->ns_nflag |= ns_nflag;
	if (waitflag == M_DONTWAIT &&
		(slp->ns_rec || (slp->ns_nflag & (SLPN_NEEDQ | SLPN_DISCONN)))) {
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		nfsrv_wakenfsd(slp);
		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	}
}

/*
 * Try and extract an RPC request from the mbuf data list received on a
 * stream socket. The "waitflag" argument indicates whether or not it
 * can sleep.
 */
static int
nfsrv_getstream(slp, waitflag)
	register struct nfssvc_sock *slp;
	int waitflag;
{
	register struct mbuf *m, **mpp;
	register char *cp1, *cp2;
	register int len;
	struct mbuf *om, *m2, *recm;
	u_long recmark;

	if (slp->ns_nflag & SLPN_GETSTREAM)
		panic("nfs getstream");
	slp->ns_nflag |= SLPN_GETSTREAM;
	for (;;) {
	    if (slp->ns_reclen == 0) {
		if (slp->ns_cc < NFSX_UNSIGNED) {
			slp->ns_nflag &= ~SLPN_GETSTREAM;
			return (0);
		}
		m = slp->ns_raw;
		if (m->m_len >= NFSX_UNSIGNED) {
			bcopy(mtod(m, caddr_t), (caddr_t)&recmark, NFSX_UNSIGNED);
			m->m_data += NFSX_UNSIGNED;
			m->m_len -= NFSX_UNSIGNED;
		} else {
			cp1 = (caddr_t)&recmark;
			cp2 = mtod(m, caddr_t);
			while (cp1 < ((caddr_t)&recmark) + NFSX_UNSIGNED) {
				while (m->m_len == 0) {
					m = m->m_next;
					cp2 = mtod(m, caddr_t);
				}
				*cp1++ = *cp2++;
				m->m_data++;
				m->m_len--;
			}
		}
		slp->ns_cc -= NFSX_UNSIGNED;
		recmark = ntohl(recmark);
		slp->ns_reclen = recmark & ~0x80000000;
		if (recmark & 0x80000000)
			slp->ns_nflag |= SLPN_LASTFRAG;
		else
			slp->ns_nflag &= ~SLPN_LASTFRAG;
		if (slp->ns_reclen < NFS_MINPACKET || slp->ns_reclen > NFS_MAXPACKET) {
			slp->ns_nflag &= ~SLPN_GETSTREAM;
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
		slp->ns_raw = slp->ns_rawend = (struct mbuf *)0;
		slp->ns_cc = slp->ns_reclen = 0;
	    } else if (slp->ns_cc > slp->ns_reclen) {
		len = 0;
		m = slp->ns_raw;
		om = (struct mbuf *)0;
		while (len < slp->ns_reclen) {
			if ((len + m->m_len) > slp->ns_reclen) {
				m2 = m_copym(m, 0, slp->ns_reclen - len,
					waitflag);
				if (m2) {
					if (om) {
						om->m_next = m2;
						recm = slp->ns_raw;
					} else
						recm = m2;
					m->m_data += slp->ns_reclen - len;
					m->m_len -= slp->ns_reclen - len;
					len = slp->ns_reclen;
				} else {
					slp->ns_nflag &= ~SLPN_GETSTREAM;
					return (EWOULDBLOCK);
				}
			} else if ((len + m->m_len) == slp->ns_reclen) {
				om = m;
				len += m->m_len;
				m = m->m_next;
				recm = slp->ns_raw;
				om->m_next = (struct mbuf *)0;
			} else {
				om = m;
				len += m->m_len;
				m = m->m_next;
			}
		}
		slp->ns_raw = m;
		slp->ns_cc -= len;
		slp->ns_reclen = 0;
	    } else {
		slp->ns_nflag &= ~SLPN_GETSTREAM;
		return (0);
	    }

	    /*
	     * Accumulate the fragments into a record.
	     */
	    mpp = &slp->ns_frag;
	    while (*mpp)
		mpp = &((*mpp)->m_next);
	    *mpp = recm;
	    if (slp->ns_nflag & SLPN_LASTFRAG) {
		if (slp->ns_recend)
		    slp->ns_recend->m_nextpkt = slp->ns_frag;
		else
		    slp->ns_rec = slp->ns_frag;
		slp->ns_recend = slp->ns_frag;
		slp->ns_frag = (struct mbuf *)0;
	    }
	}
}

/*
 * Parse an RPC header.
 */
int
nfsrv_dorec(slp, nfsd, ndp)
	register struct nfssvc_sock *slp;
	struct nfsd *nfsd;
	struct nfsrv_descript **ndp;
{
	register struct mbuf *m;
	register struct mbuf *nam;
	register struct nfsrv_descript *nd;
	int error;

	*ndp = NULL;
	if ((slp->ns_flag & SLP_VALID) == 0 ||
	    (m = slp->ns_rec) == (struct mbuf *)0)
		return (ENOBUFS);
	slp->ns_rec = m->m_nextpkt;
	if (slp->ns_rec)
		m->m_nextpkt = (struct mbuf *)0;
	else
		slp->ns_recend = (struct mbuf *)0;
	if (m->m_type == MT_SONAME) {
		nam = m;
		m = m->m_next;
		nam->m_next = NULL;
	} else
		nam = NULL;
	MALLOC_ZONE(nd, struct nfsrv_descript *,
			sizeof (struct nfsrv_descript), M_NFSRVDESC, M_WAITOK);
	nd->nd_md = nd->nd_mrep = m;
	nd->nd_nam2 = nam;
	nd->nd_dpos = mtod(m, caddr_t);
	error = nfs_getreq(nd, nfsd, TRUE);
	if (error) {
		if (nam)
			m_freem(nam);
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
	register struct nfsrv_descript *nd;
	struct nfsd *nfsd;
	int has_header;
{
	register int len, i;
	register u_long *tl;
	register long t1;
	struct uio uio;
	struct iovec iov;
	caddr_t dpos, cp2, cp;
	u_long nfsvers, auth_type;
	uid_t nickuid;
	int error = 0, nqnfs = 0, ticklen;
	struct mbuf *mrep, *md;
	register struct nfsuid *nuidp;
	struct timeval tvin, tvout, now;
#if 0				/* until encrypted keys are implemented */
	NFSKERBKEYSCHED_T keys;	/* stores key schedule */
#endif

	mrep = nd->nd_mrep;
	md = nd->nd_md;
	dpos = nd->nd_dpos;
	if (has_header) {
		nfsm_dissect(tl, u_long *, 10 * NFSX_UNSIGNED);
		nd->nd_retxid = fxdr_unsigned(u_long, *tl++);
		if (*tl++ != rpc_call) {
			m_freem(mrep);
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
		if (*tl == nqnfs_prog)
			nqnfs++;
		else {
			nd->nd_repstat = EPROGUNAVAIL;
			nd->nd_procnum = NFSPROC_NOOP;
			return (0);
		}
	}
	tl++;
	nfsvers = fxdr_unsigned(u_long, *tl++);
	if (((nfsvers < NFS_VER2 || nfsvers > NFS_VER3) && !nqnfs) ||
		(nfsvers != NQNFS_VER3 && nqnfs)) {
		nd->nd_repstat = EPROGMISMATCH;
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}
	if (nqnfs)
		nd->nd_flag = (ND_NFSV3 | ND_NQNFS);
	else if (nfsvers == NFS_VER3)
		nd->nd_flag = ND_NFSV3;
	nd->nd_procnum = fxdr_unsigned(u_long, *tl++);
	if (nd->nd_procnum == NFSPROC_NULL)
		return (0);
	if (nd->nd_procnum >= NFS_NPROCS ||
		(!nqnfs && nd->nd_procnum >= NQNFSPROC_GETLEASE) ||
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
		m_freem(mrep);
		return (EBADRPC);
	}

	nd->nd_flag &= ~ND_KERBAUTH;
	/*
	 * Handle auth_unix or auth_kerb.
	 */
	if (auth_type == rpc_auth_unix) {
		len = fxdr_unsigned(int, *++tl);
		if (len < 0 || len > NFS_MAXNAMLEN) {
			m_freem(mrep);
			return (EBADRPC);
		}
		nfsm_adv(nfsm_rndup(len));
		nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
		bzero((caddr_t)&nd->nd_cr, sizeof (struct ucred));
		nd->nd_cr.cr_ref = 1;
		nd->nd_cr.cr_uid = fxdr_unsigned(uid_t, *tl++);
		nd->nd_cr.cr_gid = fxdr_unsigned(gid_t, *tl++);
		len = fxdr_unsigned(int, *tl);
		if (len < 0 || len > RPCAUTH_UNIXGIDS) {
			m_freem(mrep);
			return (EBADRPC);
		}
		nfsm_dissect(tl, u_long *, (len + 2) * NFSX_UNSIGNED);
		for (i = 1; i <= len; i++)
		    if (i < NGROUPS)
			nd->nd_cr.cr_groups[i] = fxdr_unsigned(gid_t, *tl++);
		    else
			tl++;
		nd->nd_cr.cr_ngroups = (len >= NGROUPS) ? NGROUPS : (len + 1);
		if (nd->nd_cr.cr_ngroups > 1)
		    nfsrvw_sort(nd->nd_cr.cr_groups, nd->nd_cr.cr_ngroups);
		len = fxdr_unsigned(int, *++tl);
		if (len < 0 || len > RPCAUTH_MAXSIZ) {
			m_freem(mrep);
			return (EBADRPC);
		}
		if (len > 0)
			nfsm_adv(nfsm_rndup(len));
	} else if (auth_type == rpc_auth_kerb) {
		switch (fxdr_unsigned(int, *tl++)) {
		case RPCAKN_FULLNAME:
			ticklen = fxdr_unsigned(int, *tl);
			*((u_long *)nfsd->nfsd_authstr) = *tl;
			uio.uio_resid = nfsm_rndup(ticklen) + NFSX_UNSIGNED;
			nfsd->nfsd_authlen = uio.uio_resid + NFSX_UNSIGNED;
			if (uio.uio_resid > (len - 2 * NFSX_UNSIGNED)) {
				m_freem(mrep);
				return (EBADRPC);
			}
			uio.uio_offset = 0;
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_segflg = UIO_SYSSPACE;
			iov.iov_base = (caddr_t)&nfsd->nfsd_authstr[4];
			iov.iov_len = RPCAUTH_MAXSIZ - 4;
			nfsm_mtouio(&uio, uio.uio_resid);
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
				if (nuidp->nu_cr.cr_uid == nickuid &&
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
			nfsrv_setcred(&nuidp->nu_cr, &nd->nd_cr);
			nd->nd_flag |= ND_KERBNICK;
		};
	} else {
		nd->nd_repstat = (NFSERR_AUTHERR | AUTH_REJECTCRED);
		nd->nd_procnum = NFSPROC_NOOP;
		return (0);
	}

	/*
	 * For nqnfs, get piggybacked lease request.
	 */
	if (nqnfs && nd->nd_procnum != NQNFSPROC_EVICTED) {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		nd->nd_flag |= fxdr_unsigned(int, *tl);
		if (nd->nd_flag & ND_LEASE) {
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			nd->nd_duration = fxdr_unsigned(int, *tl);
		} else
			nd->nd_duration = NQ_MINLEASE;
	} else
		nd->nd_duration = NQ_MINLEASE;
	nd->nd_md = md;
	nd->nd_dpos = dpos;
	return (0);
nfsmout:
	return (error);
}

/*
 * Search for a sleeping nfsd and wake it up.
 * SIDE EFFECT: If none found, set NFSD_CHECKSLP flag, so that one of the
 * running nfsds will go look for the work in the nfssvc_sock list.
 */
void
nfsrv_wakenfsd(slp)
	struct nfssvc_sock *slp;
{
	register struct nfsd *nd;

	if ((slp->ns_flag & SLP_VALID) == 0)
		return;
	TAILQ_FOREACH(nd, &nfsd_head, nfsd_chain) {
		if (nd->nfsd_flag & NFSD_WAITING) {
			nd->nfsd_flag &= ~NFSD_WAITING;
			if (nd->nfsd_slp)
				panic("nfsd wakeup");
			slp->ns_sref++;
			nd->nfsd_slp = slp;
			wakeup((caddr_t)nd);
			return;
		}
	}
	slp->ns_flag |= SLP_DOREC;
	nfsd_head_flag |= NFSD_CHECKSLP;
}
#endif /* NFS_NOSERVER */

static int
nfs_msg(p, server, msg, error)
	struct proc *p;
	const char *server, *msg;
	int error;
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
nfs_down(rep, nmp, proc, msg, error, flags)
	struct nfsreq *rep;
	struct nfsmount *nmp;
	struct proc *proc;
	const char *msg;
	int error, flags;
{
	if (nmp == NULL)
		return;
	if ((flags & NFSSTA_TIMEO) && !(nmp->nm_state & NFSSTA_TIMEO)) {
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESP, 0);
		nmp->nm_state |= NFSSTA_TIMEO;
	}
	if ((flags & NFSSTA_LOCKTIMEO) && !(nmp->nm_state & NFSSTA_LOCKTIMEO)) {
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESPLOCK, 0);
		nmp->nm_state |= NFSSTA_LOCKTIMEO;
	}
	if (rep)
		rep->r_flags |= R_TPRINTFMSG;
	nfs_msg(proc, nmp->nm_mountp->mnt_stat.f_mntfromname, msg, error);
}

void
nfs_up(rep, nmp, proc, msg, flags)
	struct nfsreq *rep;
	struct nfsmount *nmp;
	struct proc *proc;
	const char *msg;
	int flags;
{
	if (nmp == NULL)
		return;
	if ((rep == NULL) || (rep->r_flags & R_TPRINTFMSG) != 0)
		nfs_msg(proc, nmp->nm_mountp->mnt_stat.f_mntfromname, msg, 0);
	if ((flags & NFSSTA_TIMEO) && (nmp->nm_state & NFSSTA_TIMEO)) {
		nmp->nm_state &= ~NFSSTA_TIMEO;
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESP, 1);
	}
	if ((flags & NFSSTA_LOCKTIMEO) && (nmp->nm_state & NFSSTA_LOCKTIMEO)) {
		nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESPLOCK, 1);
	}
}

