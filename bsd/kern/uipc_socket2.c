/*
 * Copyright (c) 1998-2010 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)uipc_socket2.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/kern/uipc_socket2.c,v 1.55.2.9 2001/07/26 18:53:02 peter Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/ev.h>
#include <kern/locks.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <sys/kdebug.h>
#include <libkern/OSAtomic.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/* TODO: this should be in a header file somewhere */
extern void postevent(struct socket *, struct sockbuf *, int);

#define DBG_FNC_SBDROP	NETDBG_CODE(DBG_NETSOCK, 4)
#define DBG_FNC_SBAPPEND	NETDBG_CODE(DBG_NETSOCK, 5)

static inline void sbcompress(struct sockbuf *, struct mbuf *, struct mbuf *);
static struct socket *sonewconn_internal(struct socket *, int);
static int sbappendaddr_internal(struct sockbuf *, struct sockaddr *,
    struct mbuf *, struct mbuf *);
static int sbappendcontrol_internal(struct sockbuf *, struct mbuf *,
    struct mbuf *);

/*
 * Primitive routines for operating on sockets and socket buffers
 */
static int soqlimitcompat = 1;
static int soqlencomp = 0;

/* Based on the number of mbuf clusters configured, high_sb_max and sb_max can get 
 * scaled up or down to suit that memory configuration. high_sb_max is a higher 
 * limit on sb_max that is checked when sb_max gets set through sysctl.
 */

u_int32_t	sb_max = SB_MAX;		/* XXX should be static */
u_int32_t	high_sb_max = SB_MAX;

static	u_int32_t sb_efficiency = 8;	/* parameter for sbreserve() */
__private_extern__ unsigned int total_mb_cnt = 0;
__private_extern__ unsigned int total_cl_cnt = 0;
__private_extern__ int sbspace_factor = 8;

/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_incomp for connections in progress
 * and so_comp for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_incomp by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_comp, making it available to accept().
 *
 * If a socket is closed with sockets on either
 * so_incomp or so_comp, these sockets are dropped.
 *
 * If higher level protocols are implemented in
 * the kernel, the wakeups done here will sometimes
 * cause software-interrupt process scheduling.
 */
void
soisconnecting(struct socket *so)
{

	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;

	sflt_notify(so, sock_evt_connecting, NULL);
}

void
soisconnected(struct socket *so)
{
	struct socket *head = so->so_head;

	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;

	sflt_notify(so, sock_evt_connected, NULL);

	if (head && (so->so_state & SS_INCOMP)) {
		so->so_state &= ~SS_INCOMP;
		so->so_state |= SS_COMP;
		if (head->so_proto->pr_getlock != NULL) {
			socket_unlock(so, 0);
			socket_lock(head, 1);
		}
		postevent(head, 0, EV_RCONN);
		TAILQ_REMOVE(&head->so_incomp, so, so_list);
		head->so_incqlen--;
		TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		sorwakeup(head);
		wakeup_one((caddr_t)&head->so_timeo);
		if (head->so_proto->pr_getlock != NULL) {
			socket_unlock(head, 1);
			socket_lock(so, 0);
		}
	} else {
		postevent(so, 0, EV_WCONN);
		wakeup((caddr_t)&so->so_timeo);
		sorwakeup(so);
		sowwakeup(so);
	}
}

void
soisdisconnecting(struct socket *so)
{
	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= (SS_ISDISCONNECTING|SS_CANTRCVMORE|SS_CANTSENDMORE);
	sflt_notify(so, sock_evt_disconnecting, NULL);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

void
soisdisconnected(struct socket *so)
{
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE|SS_ISDISCONNECTED);
	sflt_notify(so, sock_evt_disconnected, NULL);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 */
static struct socket *
sonewconn_internal(struct socket *head, int connstatus)
{
	int so_qlen, error = 0;
	struct socket *so;
	lck_mtx_t *mutex_held;

	if (head->so_proto->pr_getlock != NULL)
		mutex_held = (*head->so_proto->pr_getlock)(head, 0);
	else
		mutex_held = head->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	if (!soqlencomp) {
		/*
		 * This is the default case; so_qlen represents the
		 * sum of both incomplete and completed queues.
		 */
		so_qlen = head->so_qlen;
	} else {
		/*
		 * When kern.ipc.soqlencomp is set to 1, so_qlen
		 * represents only the completed queue.  Since we
		 * cannot let the incomplete queue goes unbounded
		 * (in case of SYN flood), we cap the incomplete
		 * queue length to at most somaxconn, and use that
		 * as so_qlen so that we fail immediately below.
		 */
		so_qlen = head->so_qlen - head->so_incqlen;
		if (head->so_incqlen > somaxconn)
			so_qlen = somaxconn;
	}

	if (so_qlen >=
	    (soqlimitcompat ? head->so_qlimit : (3 * head->so_qlimit / 2)))
		return ((struct socket *)0);
	so = soalloc(1, head->so_proto->pr_domain->dom_family,
	    head->so_type);
	if (so == NULL)
		return ((struct socket *)0);
	/* check if head was closed during the soalloc */
	if (head->so_proto == NULL) {
		sodealloc(so);
		return ((struct socket *)0);
	}

	so->so_head = head;
	so->so_type = head->so_type;
	so->so_options = head->so_options &~ SO_ACCEPTCONN;
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF;
	so->so_proto = head->so_proto;
	so->so_timeo = head->so_timeo;
	so->so_pgid  = head->so_pgid;
	so->so_uid = head->so_uid;
	/* inherit socket options stored in so_flags */
	so->so_flags = head->so_flags & (SOF_NOSIGPIPE |
					 SOF_NOADDRAVAIL |
					 SOF_REUSESHAREUID | 
					 SOF_NOTIFYCONFLICT | 
					 SOF_BINDRANDOMPORT | 
					 SOF_NPX_SETOPTSHUT);
	so->so_usecount = 1;
	so->next_lock_lr = 0;
	so->next_unlock_lr = 0;

#ifdef __APPLE__
	so->so_rcv.sb_flags |= SB_RECV;	/* XXX */
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
	TAILQ_INIT(&so->so_evlist);
#endif

#if CONFIG_MACF_SOCKET
	mac_socket_label_associate_accept(head, so);
#endif

	/* inherit traffic management properties of listener */
	so->so_traffic_mgt_flags = head->so_traffic_mgt_flags &
	    (TRAFFIC_MGT_SO_BACKGROUND | TRAFFIC_MGT_SO_BG_REGULATE);
	so->so_background_thread = head->so_background_thread;
#if PKT_PRIORITY
	so->so_traffic_class = head->so_traffic_class;
#endif /* PKT_PRIORITY */

	if (soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat)) {
		sflt_termsock(so);
		sodealloc(so);
		return ((struct socket *)0);
	}

	/*
	 * Must be done with head unlocked to avoid deadlock
	 * for protocol with per socket mutexes.
	 */
	if (head->so_proto->pr_unlock)
		socket_unlock(head, 0);
	if (((*so->so_proto->pr_usrreqs->pru_attach)(so, 0, NULL) != 0) ||
	    error) {
		sflt_termsock(so);
		sodealloc(so);
		if (head->so_proto->pr_unlock)
			socket_lock(head, 0);
		return ((struct socket *)0);
	}
	if (head->so_proto->pr_unlock)
		socket_lock(head, 0);
#ifdef __APPLE__
	so->so_proto->pr_domain->dom_refs++;
#endif

	if (connstatus) {
		TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		so->so_state |= SS_COMP;
	} else {
		TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
		so->so_state |= SS_INCOMP;
		head->so_incqlen++;
	}
	head->so_qlen++;

#ifdef __APPLE__
	/* Attach socket filters for this protocol */
	sflt_initsock(so);
#endif

	if (connstatus) {
		so->so_state |= connstatus;
		sorwakeup(head);
		wakeup((caddr_t)&head->so_timeo);
	}
	return (so);
}


struct socket *
sonewconn(struct socket *head, int connstatus, const struct sockaddr *from)
{
	int error = 0;
	struct socket_filter_entry *filter;
	int filtered = 0;

	for (filter = head->so_filt; filter && (error == 0);
	    filter = filter->sfe_next_onsocket) {
		if (filter->sfe_filter->sf_filter.sf_connect_in) {
			if (filtered == 0) {
				filtered = 1;
				sflt_use(head);
				socket_unlock(head, 0);
			}
			error = filter->sfe_filter->sf_filter.
			    sf_connect_in(filter->sfe_cookie, head, from);
		}
	}
	if (filtered != 0) {
		socket_lock(head, 0);
		sflt_unuse(head);
	}

	if (error) {
		return (NULL);
	}

	return (sonewconn_internal(head, connstatus));
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */

void
socantsendmore(struct socket *so)
{
	so->so_state |= SS_CANTSENDMORE;
	sflt_notify(so, sock_evt_cantsendmore, NULL);
	sowwakeup(so);
}

void
socantrcvmore(struct socket *so)
{
	so->so_state |= SS_CANTRCVMORE;
	sflt_notify(so, sock_evt_cantrecvmore, NULL);
	sorwakeup(so);
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 *
 * Returns:	0			Success
 *		EBADF
 *	msleep:EINTR
 */
int
sbwait(struct sockbuf *sb)
{
	int error = 0;
	uintptr_t lr_saved;
	struct socket *so = sb->sb_so;
	lck_mtx_t *mutex_held;
	struct timespec ts;

	lr_saved = (uintptr_t) __builtin_return_address(0);

	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;

	sb->sb_flags |= SB_WAIT;

	if (so->so_usecount < 1)
		panic("sbwait: so=%p refcount=%d\n", so, so->so_usecount);
	ts.tv_sec = sb->sb_timeo.tv_sec;
	ts.tv_nsec = sb->sb_timeo.tv_usec * 1000;
	error = msleep((caddr_t)&sb->sb_cc, mutex_held,
	    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH, "sbwait", &ts);

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	if (so->so_usecount < 1)
		panic("sbwait: so=%p refcount=%d\n", so, so->so_usecount);

	if ((so->so_state & SS_DRAINING)) {
		error = EBADF;
	}

	return (error);
}

/*
 * Lock a sockbuf already known to be locked;
 * return any error returned from sleep (EINTR).
 *
 * Returns:	0			Success
 *		EINTR
 */
int
sb_lock(struct sockbuf *sb)
{
	struct socket *so = sb->sb_so;
	lck_mtx_t *mutex_held;
	int error = 0;

	if (so == NULL)
		panic("sb_lock: null so back pointer sb=%p\n", sb);

	while (sb->sb_flags & SB_LOCK) {
		sb->sb_flags |= SB_WANT;
		if (so->so_proto->pr_getlock != NULL)
			mutex_held = (*so->so_proto->pr_getlock)(so, 0);
		else
			mutex_held = so->so_proto->pr_domain->dom_mtx;
		if (so->so_usecount < 1)
			panic("sb_lock: so=%p refcount=%d\n", so,
			    so->so_usecount);

		error = msleep((caddr_t)&sb->sb_flags, mutex_held,
		    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH,
		    "sb_lock", 0);
		if (so->so_usecount < 1)
			panic("sb_lock: 2 so=%p refcount=%d\n", so,
			    so->so_usecount);
		if (error)
			return (error);
	}
	sb->sb_flags |= SB_LOCK;
	return (0);
}

/*
 * Wakeup processes waiting on a socket buffer.
 * Do asynchronous notification via SIGIO
 * if the socket has the SS_ASYNC flag set.
 */
void
sowakeup(struct socket *so, struct sockbuf *sb)
{
	sb->sb_flags &= ~SB_SEL;
	selwakeup(&sb->sb_sel);
	if (sb->sb_flags & SB_WAIT) {
		sb->sb_flags &= ~SB_WAIT;
		wakeup((caddr_t)&sb->sb_cc);
	}
	if (so->so_state & SS_ASYNC) {
		if (so->so_pgid < 0)
			gsignal(-so->so_pgid, SIGIO);
		else if (so->so_pgid > 0)
			proc_signal(so->so_pgid, SIGIO);
	}
	if (sb->sb_flags & SB_KNOTE) {
		KNOTE(&sb->sb_sel.si_note, SO_FILT_HINT_LOCKED);
	}
	if (sb->sb_flags & SB_UPCALL) {
		void (*so_upcall)(struct socket *, caddr_t, int);
		caddr_t so_upcallarg;

		so_upcall = so->so_upcall;
		so_upcallarg = so->so_upcallarg;
		/* Let close know that we're about to do an upcall */
		so->so_flags |= SOF_UPCALLINUSE;

		socket_unlock(so, 0);
		(*so_upcall)(so, so_upcallarg, M_DONTWAIT);
		socket_lock(so, 0);

		so->so_flags &= ~SOF_UPCALLINUSE;
		/* Tell close that it's safe to proceed */
		if (so->so_flags & SOF_CLOSEWAIT)
			wakeup((caddr_t)&so->so_upcall);
	}
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and
 * one for receiving data.  Each buffer contains a queue of mbufs,
 * information about the number of mbufs and amount of data in the
 * queue, and other fields allowing select() statements and notification
 * on data availability to be implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.
 * Each record is a list of mbufs chained together with the m_next
 * field.  Records are chained together with the m_nextpkt field. The upper
 * level routine soreceive() expects the following conventions to be
 * observed when placing information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's
 *    name, then a record containing that name must be present before
 *    any associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really
 *    just additional data associated with the message), and there are
 *    ``rights'' to be received, then a record containing this data
 *    should be present (mbuf's must be of type MT_RIGHTS).
 * 3. If a name or rights record exists, then it must be followed by
 *    a data record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space
 * should be released by calling sbrelease() when the socket is destroyed.
 */

/*
 * Returns:	0			Success
 *		ENOBUFS
 */
int
soreserve(struct socket *so, u_int32_t sndcc, u_int32_t rcvcc)
{

	if (sbreserve(&so->so_snd, sndcc) == 0)
		goto bad;
	if (sbreserve(&so->so_rcv, rcvcc) == 0)
		goto bad2;
	if (so->so_rcv.sb_lowat == 0)
		so->so_rcv.sb_lowat = 1;
	if (so->so_snd.sb_lowat == 0)
		so->so_snd.sb_lowat = MCLBYTES;
	if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat)
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
	return (0);
bad2:
#ifdef __APPLE__
	selthreadclear(&so->so_snd.sb_sel);
#endif
	sbrelease(&so->so_snd);
bad:
	return (ENOBUFS);
}

/*
 * Allot mbufs to a sockbuf.
 * Attempt to scale mbmax so that mbcnt doesn't become limiting
 * if buffering efficiency is near the normal case.
 */
int
sbreserve(struct sockbuf *sb, u_int32_t cc)
{
	if ((u_quad_t)cc > (u_quad_t)sb_max * MCLBYTES / (MSIZE + MCLBYTES))
		return (0);
	sb->sb_hiwat = cc;
	sb->sb_mbmax = min(cc * sb_efficiency, sb_max);
	if (sb->sb_lowat > sb->sb_hiwat)
		sb->sb_lowat = sb->sb_hiwat;
	return (1);
}

/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
/*  WARNING needs to do selthreadclear() before calling this */
void
sbrelease(struct sockbuf *sb)
{
	sbflush(sb);
	sb->sb_hiwat = 0;
	sb->sb_mbmax = 0;
}

/*
 * Routines to add and remove
 * data from an mbuf queue.
 *
 * The routines sbappend() or sbappendrecord() are normally called to
 * append new mbufs to a socket buffer, after checking that adequate
 * space is available, comparing the function sbspace() with the amount
 * of data to be added.  sbappendrecord() differs from sbappend() in
 * that data supplied is treated as the beginning of a new record.
 * To place a sender's address, optional access rights, and data in a
 * socket receive buffer, sbappendaddr() should be used.  To place
 * access rights and data in a socket receive buffer, sbappendrights()
 * should be used.  In either case, the new data begins a new record.
 * Note that unlike sbappend() and sbappendrecord(), these routines check
 * for the caller that there will be enough space to store the data.
 * Each fails if there is not enough space, or if it cannot find mbufs
 * to store additional information in.
 *
 * Reliable protocols may use the socket send buffer to hold data
 * awaiting acknowledgement.  Data is normally copied from a socket
 * send buffer in a protocol with m_copy for output to a peer,
 * and then removing the data from the socket buffer with sbdrop()
 * or sbdroprecord() when the data is acknowledged by the peer.
 */

/*
 * Append mbuf chain m to the last record in the
 * socket buffer sb.  The additional space associated
 * the mbuf chain is recorded in sb.  Empty mbufs are
 * discarded and mbufs are compacted where possible.
 */
int
sbappend(struct sockbuf *sb, struct mbuf *m)
{
	struct socket *so = sb->sb_so;

	if (m == NULL || (sb->sb_flags & SB_DROP)) {
		if (m != NULL)
			m_freem(m);
		return (0);
	}

	SBLASTRECORDCHK(sb, "sbappend 1");

	if (sb->sb_lastrecord != NULL && (sb->sb_mbtail->m_flags & M_EOR))
		return (sbappendrecord(sb, m));

	if (sb->sb_flags & SB_RECV) {
		int error = sflt_data_in(so, NULL, &m, NULL, 0, NULL);
		SBLASTRECORDCHK(sb, "sbappend 2");
		if (error != 0) {
			if (error != EJUSTRETURN)
				m_freem(m);
			return (0);
		}
	}

	/* If this is the first record, it's also the last record */
	if (sb->sb_lastrecord == NULL)
		sb->sb_lastrecord = m;

	sbcompress(sb, m, sb->sb_mbtail);
	SBLASTRECORDCHK(sb, "sbappend 3");
	return (1);
}

/*
 * Similar to sbappend, except that this is optimized for stream sockets.
 */
int
sbappendstream(struct sockbuf *sb, struct mbuf *m)
{
	struct socket *so = sb->sb_so;

	if (m->m_nextpkt != NULL || (sb->sb_mb != sb->sb_lastrecord))
		panic("sbappendstream: nexpkt %p || mb %p != lastrecord %p\n",
		    m->m_nextpkt, sb->sb_mb, sb->sb_lastrecord);

	SBLASTMBUFCHK(sb, __func__);

	if (m == NULL || (sb->sb_flags & SB_DROP)) {
		if (m != NULL)
			m_freem(m);
		return (0);
	}

	if (sb->sb_flags & SB_RECV) {
		int error = sflt_data_in(so, NULL, &m, NULL, 0, NULL);
		SBLASTRECORDCHK(sb, "sbappendstream 1");
		if (error != 0) {
			if (error != EJUSTRETURN)
				m_freem(m);
			return (0);
		}
	}

	sbcompress(sb, m, sb->sb_mbtail);
	sb->sb_lastrecord = sb->sb_mb;
	SBLASTRECORDCHK(sb, "sbappendstream 2");
	return (1);
}

#ifdef SOCKBUF_DEBUG
void
sbcheck(struct sockbuf *sb)
{
	struct mbuf *m;
	struct mbuf *n = 0;
	u_int32_t len = 0, mbcnt = 0;
	lck_mtx_t *mutex_held;

	if (sb->sb_so->so_proto->pr_getlock != NULL)
		mutex_held = (*sb->sb_so->so_proto->pr_getlock)(sb->sb_so, 0);
	else
		mutex_held = sb->sb_so->so_proto->pr_domain->dom_mtx;

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	if (sbchecking == 0)
		return;

	for (m = sb->sb_mb; m; m = n) {
		n = m->m_nextpkt;
		for (; m; m = m->m_next) {
			len += m->m_len;
			mbcnt += MSIZE;
			/* XXX pretty sure this is bogus */
			if (m->m_flags & M_EXT)
				mbcnt += m->m_ext.ext_size;
		}
	}
	if (len != sb->sb_cc || mbcnt != sb->sb_mbcnt) {
		panic("cc %ld != %ld || mbcnt %ld != %ld\n", len, sb->sb_cc,
		    mbcnt, sb->sb_mbcnt);
	}
}
#endif

void
sblastrecordchk(struct sockbuf *sb, const char *where)
{
	struct mbuf *m = sb->sb_mb;

	while (m && m->m_nextpkt)
		m = m->m_nextpkt;

	if (m != sb->sb_lastrecord) {
		printf("sblastrecordchk: mb %p lastrecord %p last %p\n",
		    sb->sb_mb, sb->sb_lastrecord, m);
		printf("packet chain:\n");
		for (m = sb->sb_mb; m != NULL; m = m->m_nextpkt)
			printf("\t%p\n", m);
		panic("sblastrecordchk from %s", where);
	}
}

void
sblastmbufchk(struct sockbuf *sb, const char *where)
{
	struct mbuf *m = sb->sb_mb;
	struct mbuf *n;

	while (m && m->m_nextpkt)
		m = m->m_nextpkt;

	while (m && m->m_next)
		m = m->m_next;

	if (m != sb->sb_mbtail) {
		printf("sblastmbufchk: mb %p mbtail %p last %p\n",
		    sb->sb_mb, sb->sb_mbtail, m);
		printf("packet tree:\n");
		for (m = sb->sb_mb; m != NULL; m = m->m_nextpkt) {
			printf("\t");
			for (n = m; n != NULL; n = n->m_next)
				printf("%p ", n);
			printf("\n");
		}
		panic("sblastmbufchk from %s", where);
	}
}

/*
 * Similar to sbappend, except the mbuf chain begins a new record.
 */
int
sbappendrecord(struct sockbuf *sb, struct mbuf *m0)
{
	struct mbuf *m;
	int space = 0;

	if (m0 == NULL || (sb->sb_flags & SB_DROP)) {
		if (m0 != NULL)
			m_freem(m0);
		return (0);
	}

	for (m = m0; m != NULL; m = m->m_next)
		space += m->m_len;

	if (space > sbspace(sb) && !(sb->sb_flags & SB_UNIX)) {
		m_freem(m0);
		return (0);
	}

	if (sb->sb_flags & SB_RECV) {
		int error = sflt_data_in(sb->sb_so, NULL, &m0, NULL,
		    sock_data_filt_flag_record, NULL);
		if (error != 0) {
			SBLASTRECORDCHK(sb, "sbappendrecord 1");
			if (error != EJUSTRETURN)
				m_freem(m0);
			return (0);
		}
	}

	/*
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	SBLASTRECORDCHK(sb, "sbappendrecord 2");
	if (sb->sb_lastrecord != NULL) {
		sb->sb_lastrecord->m_nextpkt = m0;
	}  else {
		sb->sb_mb = m0;
	}
	sb->sb_lastrecord = m0;
	sb->sb_mbtail = m0;

	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
	SBLASTRECORDCHK(sb, "sbappendrecord 3");
	return (1);
}

/*
 * As above except that OOB data
 * is inserted at the beginning of the sockbuf,
 * but after any other OOB data.
 */
int
sbinsertoob(struct sockbuf *sb, struct mbuf *m0)
{
	struct mbuf *m;
	struct mbuf **mp;

	if (m0 == 0)
		return (0);

	SBLASTRECORDCHK(sb, "sbinsertoob 1");

	if ((sb->sb_flags & SB_RECV) != 0) {
		int error = sflt_data_in(sb->sb_so, NULL, &m0, NULL,
		    sock_data_filt_flag_oob, NULL);

		SBLASTRECORDCHK(sb, "sbinsertoob 2");
		if (error) {
			if (error != EJUSTRETURN) {
				m_freem(m0);
			}
			return (0);
		}
	}

	for (mp = &sb->sb_mb; *mp; mp = &((*mp)->m_nextpkt)) {
		m = *mp;
again:
		switch (m->m_type) {

		case MT_OOBDATA:
			continue;		/* WANT next train */

		case MT_CONTROL:
			m = m->m_next;
			if (m)
				goto again;	/* inspect THIS train further */
		}
		break;
	}
	/*
	 * Put the first mbuf on the queue.
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	m0->m_nextpkt = *mp;
	if (*mp == NULL) {
		/* m0 is actually the new tail */
		sb->sb_lastrecord = m0;
	}
	*mp = m0;
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
	SBLASTRECORDCHK(sb, "sbinsertoob 3");
	return (1);
}

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 *
 * Returns:	0			No space/out of mbufs
 *		1			Success
 */
static int
sbappendaddr_internal(struct sockbuf *sb, struct sockaddr *asa,
    struct mbuf *m0, struct mbuf *control)
{
	struct mbuf *m, *n, *nlast;
	int space = asa->sa_len;

	if (m0 && (m0->m_flags & M_PKTHDR) == 0)
		panic("sbappendaddr");

	if (m0)
		space += m0->m_pkthdr.len;
	for (n = control; n; n = n->m_next) {
		space += n->m_len;
		if (n->m_next == 0)	/* keep pointer to last control buf */
			break;
	}
	if (space > sbspace(sb))
		return (0);
	if (asa->sa_len > MLEN)
		return (0);
	MGET(m, M_DONTWAIT, MT_SONAME);
	if (m == 0)
		return (0);
	m->m_len = asa->sa_len;
	bcopy((caddr_t)asa, mtod(m, caddr_t), asa->sa_len);
	if (n)
		n->m_next = m0;		/* concatenate data to control */
	else
		control = m0;
	m->m_next = control;

	SBLASTRECORDCHK(sb, "sbappendadddr 1");

	for (n = m; n->m_next != NULL; n = n->m_next)
		sballoc(sb, n);
	sballoc(sb, n);
	nlast = n;

	if (sb->sb_lastrecord != NULL) {
		sb->sb_lastrecord->m_nextpkt = m;
	} else {
		sb->sb_mb = m;
	}
	sb->sb_lastrecord = m;
	sb->sb_mbtail = nlast;

	SBLASTMBUFCHK(sb, __func__);
	SBLASTRECORDCHK(sb, "sbappendadddr 2");

	postevent(0, sb, EV_RWBYTES);
	return (1);
}

/*
 * Returns:	0			Error: No space/out of mbufs/etc.
 *		1			Success
 *
 * Imputed:	(*error_out)		errno for error
 *		ENOBUFS
 *	sflt_data_in:???		[whatever a filter author chooses]
 */
int
sbappendaddr(struct sockbuf *sb, struct sockaddr *asa, struct mbuf *m0,
    struct mbuf *control, int *error_out)
{
	int result = 0;
	boolean_t sb_unix = (sb->sb_flags & SB_UNIX);

	if (error_out)
		*error_out = 0;

	if (m0 && (m0->m_flags & M_PKTHDR) == 0)
		panic("sbappendaddrorfree");

	if (sb->sb_flags & SB_DROP) {
		if (m0 != NULL)
			m_freem(m0);
		if (control != NULL && !sb_unix)
			m_freem(control);
		if (error_out != NULL)
			*error_out = EINVAL;
		return (0);
	}

	/* Call socket data in filters */
	if ((sb->sb_flags & SB_RECV) != 0) {
		int error;
		error = sflt_data_in(sb->sb_so, asa, &m0, &control, 0, NULL);
		SBLASTRECORDCHK(sb, __func__);
		if (error) {
			if (error != EJUSTRETURN) {
				if (m0)
					m_freem(m0);
				if (control != NULL && !sb_unix)
					m_freem(control);
				if (error_out)
					*error_out = error;
			}
			return (0);
		}
	}

	result = sbappendaddr_internal(sb, asa, m0, control);
	if (result == 0) {
		if (m0)
			m_freem(m0);
		if (control != NULL && !sb_unix)
			m_freem(control);
		if (error_out)
			*error_out = ENOBUFS;
	}

	return (result);
}

static int
sbappendcontrol_internal(struct sockbuf *sb, struct mbuf *m0,
    struct mbuf *control)
{
	struct mbuf *m, *mlast, *n;
	int space = 0;

	if (control == 0)
		panic("sbappendcontrol");

	for (m = control; ; m = m->m_next) {
		space += m->m_len;
		if (m->m_next == 0)
			break;
	}
	n = m;			/* save pointer to last control buffer */
	for (m = m0; m; m = m->m_next)
		space += m->m_len;
	if (space > sbspace(sb) && !(sb->sb_flags & SB_UNIX))
		return (0);
	n->m_next = m0;			/* concatenate data to control */

	SBLASTRECORDCHK(sb, "sbappendcontrol 1");

	for (m = control; m->m_next != NULL; m = m->m_next)
		sballoc(sb, m);
	sballoc(sb, m);
	mlast = m;

	if (sb->sb_lastrecord != NULL) {
		sb->sb_lastrecord->m_nextpkt = control;
	} else {
		sb->sb_mb = control;
	}
	sb->sb_lastrecord = control;
	sb->sb_mbtail = mlast;

	SBLASTMBUFCHK(sb, __func__);
	SBLASTRECORDCHK(sb, "sbappendcontrol 2");

	postevent(0, sb, EV_RWBYTES);
	return (1);
}

int
sbappendcontrol(struct sockbuf *sb, struct mbuf	*m0, struct mbuf *control,
    int *error_out)
{
	int result = 0;
	boolean_t sb_unix = (sb->sb_flags & SB_UNIX);

	if (error_out)
		*error_out = 0;

	if (sb->sb_flags & SB_DROP) {
		if (m0 != NULL)
			m_freem(m0);
		if (control != NULL && !sb_unix)
			m_freem(control);
		if (error_out != NULL)
			*error_out = EINVAL;
		return (0);
	}

	if (sb->sb_flags & SB_RECV) {
		int error;

		error = sflt_data_in(sb->sb_so, NULL, &m0, &control, 0, NULL);
		SBLASTRECORDCHK(sb, __func__);
		if (error) {
			if (error != EJUSTRETURN) {
				if (m0)
					m_freem(m0);
				if (control != NULL && !sb_unix)
					m_freem(control);
				if (error_out)
					*error_out = error;
			}
			return (0);
		}
	}

	result = sbappendcontrol_internal(sb, m0, control);
	if (result == 0) {
		if (m0)
			m_freem(m0);
		if (control != NULL && !sb_unix)
			m_freem(control);
		if (error_out)
			*error_out = ENOBUFS;
	}

	return (result);
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
static inline void
sbcompress(struct sockbuf *sb, struct mbuf *m, struct mbuf *n)
{
	int eor = 0;
	struct mbuf *o;

	if (m == NULL) {
		/* There is nothing to compress; just update the tail */
		for (; n->m_next != NULL; n = n->m_next)
			;
		sb->sb_mbtail = n;
		goto done;
	}

	while (m) {
		eor |= m->m_flags & M_EOR;
		if (m->m_len == 0 && (eor == 0 ||
		    (((o = m->m_next) || (o = n)) && o->m_type == m->m_type))) {
			if (sb->sb_lastrecord == m)
				sb->sb_lastrecord = m->m_next;
			m = m_free(m);
			continue;
		}
		if (n && (n->m_flags & M_EOR) == 0 &&
#ifndef __APPLE__
		    M_WRITABLE(n) &&
#endif
		    m->m_len <= MCLBYTES / 4 && /* XXX: Don't copy too much */
		    m->m_len <= M_TRAILINGSPACE(n) &&
		    n->m_type == m->m_type) {
			bcopy(mtod(m, caddr_t), mtod(n, caddr_t) + n->m_len,
			    (unsigned)m->m_len);
			n->m_len += m->m_len;
			sb->sb_cc += m->m_len;
			if (m->m_type != MT_DATA && m->m_type != MT_HEADER &&
				m->m_type != MT_OOBDATA)
				/* XXX: Probably don't need.*/
				sb->sb_ctl += m->m_len;
			m = m_free(m);
			continue;
		}
		if (n)
			n->m_next = m;
		else
			sb->sb_mb = m;
		sb->sb_mbtail = m;
		sballoc(sb, m);
		n = m;
		m->m_flags &= ~M_EOR;
		m = m->m_next;
		n->m_next = 0;
	}
	if (eor) {
		if (n)
			n->m_flags |= eor;
		else
			printf("semi-panic: sbcompress\n");
	}
done:
	SBLASTMBUFCHK(sb, __func__);
	postevent(0, sb, EV_RWBYTES);
}

void
sb_empty_assert(struct sockbuf *sb, const char *where)
{
	if (!(sb->sb_cc == 0 && sb->sb_mb == NULL && sb->sb_mbcnt == 0 &&
	    sb->sb_mbtail == NULL && sb->sb_lastrecord == NULL)) {
		panic("%s: sb %p so %p cc %d mbcnt %d mb %p mbtail %p "
		    "lastrecord %p\n", where, sb, sb->sb_so, sb->sb_cc,
		    sb->sb_mbcnt, sb->sb_mb, sb->sb_mbtail, sb->sb_lastrecord);
		/* NOTREACHED */
	}
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
void
sbflush(struct sockbuf *sb)
{
	if (sb->sb_so == NULL)
		panic("sbflush sb->sb_so already null sb=%p\n", sb);
	(void) sblock(sb, M_WAIT);
	while (sb->sb_mbcnt) {
		/*
		 * Don't call sbdrop(sb, 0) if the leading mbuf is non-empty:
		 * we would loop forever. Panic instead.
		 */
		if (!sb->sb_cc && (sb->sb_mb == NULL || sb->sb_mb->m_len))
			break;
		sbdrop(sb, (int)sb->sb_cc);
	}
	sb_empty_assert(sb, __func__);
	postevent(0, sb, EV_RWBYTES);
	sbunlock(sb, 1);	/* keep socket locked */

}

/*
 * Drop data from (the front of) a sockbuf.
 * use m_freem_list to free the mbuf structures
 * under a single lock... this is done by pruning
 * the top of the tree from the body by keeping track
 * of where we get to in the tree and then zeroing the
 * two pertinent pointers m_nextpkt and m_next
 * the socket buffer is then updated to point at the new
 * top of the tree and the pruned area is released via
 * m_freem_list.
 */
void
sbdrop(struct sockbuf *sb, int len)
{
	struct mbuf *m, *free_list, *ml;
	struct mbuf *next, *last;

	KERNEL_DEBUG((DBG_FNC_SBDROP | DBG_FUNC_START), sb, len, 0, 0, 0);

	next = (m = sb->sb_mb) ? m->m_nextpkt : 0;
	free_list = last = m;
	ml = (struct mbuf *)0;

	while (len > 0) {
		if (m == 0) {
			if (next == 0) {
				/*
				 * temporarily replacing this panic with printf
				 * because it occurs occasionally when closing
				 * a socket when there is no harm in ignoring
				 * it. This problem will be investigated
				 * further.
				 */
				/* panic("sbdrop"); */
				printf("sbdrop - count not zero\n");
				len = 0;
				/*
				 * zero the counts. if we have no mbufs,
				 * we have no data (PR-2986815)
				 */
				sb->sb_cc = 0;
				sb->sb_mbcnt = 0;
				break;
			}
			m = last = next;
			next = m->m_nextpkt;
			continue;
		}
		if (m->m_len > len) {
			m->m_len -= len;
			m->m_data += len;
			sb->sb_cc -= len;
			if (m->m_type != MT_DATA && m->m_type != MT_HEADER &&
				m->m_type != MT_OOBDATA)
				sb->sb_ctl -= len;
			break;
		}
		len -= m->m_len;
		sbfree(sb, m);

		ml = m;
		m = m->m_next;
	}
	while (m && m->m_len == 0) {
		sbfree(sb, m);

		ml = m;
		m = m->m_next;
	}
	if (ml) {
		ml->m_next = (struct mbuf *)0;
		last->m_nextpkt = (struct mbuf *)0;
		m_freem_list(free_list);
	}
	if (m) {
		sb->sb_mb = m;
		m->m_nextpkt = next;
	} else {
		sb->sb_mb = next;
	}

	/*
	 * First part is an inline SB_EMPTY_FIXUP().  Second part
	 * makes sure sb_lastrecord is up-to-date if we dropped
	 * part of the last record.
	 */
	m = sb->sb_mb;
	if (m == NULL) {
		sb->sb_mbtail = NULL;
		sb->sb_lastrecord = NULL;
	} else if (m->m_nextpkt == NULL) {
		sb->sb_lastrecord = m;
	}

	postevent(0, sb, EV_RWBYTES);

	KERNEL_DEBUG((DBG_FNC_SBDROP | DBG_FUNC_END), sb, 0, 0, 0, 0);
}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
void
sbdroprecord(struct sockbuf *sb)
{
	struct mbuf *m, *mn;

	m = sb->sb_mb;
	if (m) {
		sb->sb_mb = m->m_nextpkt;
		do {
			sbfree(sb, m);
			MFREE(m, mn);
			m = mn;
		} while (m);
	}
	SB_EMPTY_FIXUP(sb);
	postevent(0, sb, EV_RWBYTES);
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation on a socket buffer.
 */
struct mbuf *
sbcreatecontrol(caddr_t p, int size, int type, int level)
{
	struct cmsghdr *cp;
	struct mbuf *m;

	if (CMSG_SPACE((u_int)size) > MLEN)
		return ((struct mbuf *)NULL);
	if ((m = m_get(M_DONTWAIT, MT_CONTROL)) == NULL)
		return ((struct mbuf *)NULL);
	cp = mtod(m, struct cmsghdr *);
	/* XXX check size? */
	(void) memcpy(CMSG_DATA(cp), p, size);
	m->m_len = CMSG_SPACE(size);
	cp->cmsg_len = CMSG_LEN(size);
	cp->cmsg_level = level;
	cp->cmsg_type = type;
	return (m);
}

/*
 * Some routines that return EOPNOTSUPP for entry points that are not
 * supported by a protocol.  Fill in as needed.
 */
int
pru_abort_notsupp(__unused struct socket *so)
{
	return (EOPNOTSUPP);
}

int
pru_accept_notsupp(__unused struct socket *so, __unused struct sockaddr **nam)
{
	return (EOPNOTSUPP);
}

int
pru_attach_notsupp(__unused struct socket *so, __unused int proto,
    __unused struct proc *p)
{
	return (EOPNOTSUPP);
}

int
pru_bind_notsupp(__unused struct socket *so, __unused struct sockaddr *nam,
    __unused struct proc *p)
{
	return (EOPNOTSUPP);
}

int
pru_connect_notsupp(__unused struct socket *so, __unused struct sockaddr *nam,
    __unused struct proc *p)
{
	return (EOPNOTSUPP);
}

int
pru_connect2_notsupp(__unused struct socket *so1, __unused struct socket *so2)
{
	return (EOPNOTSUPP);
}

int
pru_control_notsupp(__unused struct socket *so, __unused u_long  cmd,
    __unused caddr_t data, __unused struct ifnet *ifp, __unused struct proc *p)
{
	return (EOPNOTSUPP);
}

int
pru_detach_notsupp(__unused struct socket *so)
{
	return (EOPNOTSUPP);
}

int
pru_disconnect_notsupp(__unused struct socket *so)
{
	return (EOPNOTSUPP);
}

int
pru_listen_notsupp(__unused struct socket *so, __unused struct proc *p)
{
	return (EOPNOTSUPP);
}

int
pru_peeraddr_notsupp(__unused struct socket *so, __unused struct sockaddr **nam)
{
	return (EOPNOTSUPP);
}

int
pru_rcvd_notsupp(__unused struct socket *so, __unused int flags)
{
	return (EOPNOTSUPP);
}

int
pru_rcvoob_notsupp(__unused struct socket *so, __unused struct mbuf *m,
    __unused int flags)
{
	return (EOPNOTSUPP);
}

int
pru_send_notsupp(__unused struct socket *so, __unused int flags,
    __unused struct mbuf *m, __unused struct sockaddr *addr,
    __unused struct mbuf *control, __unused struct proc *p)

{
	return (EOPNOTSUPP);
}


/*
 * This isn't really a ``null'' operation, but it's the default one
 * and doesn't do anything destructive.
 */
int
pru_sense_null(struct socket *so, void *ub, int isstat64)
{
	if (isstat64 != 0) {
		struct stat64 *sb64;

		sb64 = (struct stat64 *)ub;
		sb64->st_blksize = so->so_snd.sb_hiwat;
	} else {
		struct stat *sb;

		sb = (struct stat *)ub;
		sb->st_blksize = so->so_snd.sb_hiwat;
	}

	return (0);
}


int
pru_sosend_notsupp(__unused struct socket *so, __unused struct sockaddr *addr,
    __unused struct uio *uio, __unused struct mbuf *top,
    __unused struct mbuf *control, __unused int flags)

{
	return (EOPNOTSUPP);
}

int
pru_soreceive_notsupp(__unused struct socket *so,
    __unused struct sockaddr **paddr,
    __unused struct uio *uio, __unused struct mbuf **mp0,
    __unused struct mbuf **controlp, __unused int *flagsp)
{
	return (EOPNOTSUPP);
}

int
pru_shutdown_notsupp(__unused struct socket *so)
{
	return (EOPNOTSUPP);
}

int
pru_sockaddr_notsupp(__unused struct socket *so, __unused struct sockaddr **nam)
{
	return (EOPNOTSUPP);
}

int
pru_sopoll_notsupp(__unused struct socket *so, __unused int events,
    __unused kauth_cred_t cred, __unused void *wql)
{
	return (EOPNOTSUPP);
}


#ifdef __APPLE__
/*
 * The following are macros on BSD and functions on Darwin
 */

/*
 * Do we need to notify the other side when I/O is possible?
 */

int
sb_notify(struct sockbuf *sb)
{
	return ((sb->sb_flags &
	    (SB_WAIT|SB_SEL|SB_ASYNC|SB_UPCALL|SB_KNOTE)) != 0);
}

/*
 * How much space is there in a socket buffer (so->so_snd or so->so_rcv)?
 * This is problematical if the fields are unsigned, as the space might
 * still be negative (cc > hiwat or mbcnt > mbmax).  Should detect
 * overflow and return 0.  
 */
int
sbspace(struct sockbuf *sb)
{
	int space =
		imin((int)(sb->sb_hiwat - sb->sb_cc),
	    	(int)(sb->sb_mbmax - sb->sb_mbcnt));
	if (space < 0)
		space = 0;

	return space;
}

/* do we have to send all at once on a socket? */
int
sosendallatonce(struct socket *so)
{
	return (so->so_proto->pr_flags & PR_ATOMIC);
}

/* can we read something from so? */
int
soreadable(struct socket *so)
{
	return (so->so_rcv.sb_cc >= so->so_rcv.sb_lowat ||
	    (so->so_state & SS_CANTRCVMORE) ||
	    so->so_comp.tqh_first || so->so_error);
}

/* can we write something to so? */

int
sowriteable(struct socket *so)
{
	return ((sbspace(&(so)->so_snd) >= (so)->so_snd.sb_lowat &&
	    ((so->so_state&SS_ISCONNECTED) ||
	    (so->so_proto->pr_flags&PR_CONNREQUIRED) == 0)) ||
	    (so->so_state & SS_CANTSENDMORE) ||
	    so->so_error);
}

/* adjust counters in sb reflecting allocation of m */

void
sballoc(struct sockbuf *sb, struct mbuf *m)
{
	int cnt = 1;
	sb->sb_cc += m->m_len; 
	if (m->m_type != MT_DATA && m->m_type != MT_HEADER && 
		m->m_type != MT_OOBDATA)
		sb->sb_ctl += m->m_len;
	sb->sb_mbcnt += MSIZE; 
	
	if (m->m_flags & M_EXT) {
		sb->sb_mbcnt += m->m_ext.ext_size; 
		cnt += m->m_ext.ext_size / MSIZE ;
	}
	OSAddAtomic(cnt, &total_mb_cnt);
}

/* adjust counters in sb reflecting freeing of m */
void
sbfree(struct sockbuf *sb, struct mbuf *m)
{
	int cnt = -1;
	sb->sb_cc -= m->m_len;
	if (m->m_type != MT_DATA && m->m_type != MT_HEADER &&     
		m->m_type != MT_OOBDATA)
		sb->sb_ctl -= m->m_len;
	sb->sb_mbcnt -= MSIZE; 
	if (m->m_flags & M_EXT) {
		sb->sb_mbcnt -= m->m_ext.ext_size; 
		cnt -= m->m_ext.ext_size / MSIZE ;
	}
	OSAddAtomic(cnt, &total_mb_cnt);
}

/*
 * Set lock on sockbuf sb; sleep if lock is already held.
 * Unless SB_NOINTR is set on sockbuf, sleep is interruptible.
 * Returns error without lock if sleep is interrupted.
 *
 * Returns:	0			Success
 *		EWOULDBLOCK
 *	sb_lock:EINTR
 */
int
sblock(struct sockbuf *sb, int wf)
{
	int error = 0;

	if (sb->sb_flags & SB_LOCK)
		error = (wf == M_WAIT) ? sb_lock(sb) : EWOULDBLOCK;
	else
		sb->sb_flags |= SB_LOCK;

	return (error);
}

/* release lock on sockbuf sb */
void
sbunlock(struct sockbuf *sb, int keeplocked)
{
	struct socket *so = sb->sb_so;
	void *lr_saved;
	lck_mtx_t *mutex_held;

	lr_saved = __builtin_return_address(0);

	sb->sb_flags &= ~SB_LOCK;

	if (sb->sb_flags & SB_WANT) {
		sb->sb_flags &= ~SB_WANT;
		if (so->so_usecount < 0) {
			panic("sbunlock: b4 wakeup so=%p ref=%d lr=%p "
			    "sb_flags=%x lrh= %s\n", sb->sb_so, so->so_usecount,
			    lr_saved, sb->sb_flags, solockhistory_nr(so));
			/* NOTREACHED */
		}
		wakeup((caddr_t)&(sb)->sb_flags);
	}
	if (keeplocked == 0) {	/* unlock on exit */
		if (so->so_proto->pr_getlock != NULL)
			mutex_held = (*so->so_proto->pr_getlock)(so, 0);
		else
			mutex_held = so->so_proto->pr_domain->dom_mtx;

		lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

		so->so_usecount--;
		if (so->so_usecount < 0)
			panic("sbunlock: unlock on exit so=%p ref=%d lr=%p "
			    "sb_flags=%x lrh= %s\n", so, so->so_usecount, lr_saved,
			    sb->sb_flags, solockhistory_nr(so));
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
		lck_mtx_unlock(mutex_held);
	}
}

void
sorwakeup(struct socket *so)
{
	if (sb_notify(&so->so_rcv))
		sowakeup(so, &so->so_rcv);
}

void
sowwakeup(struct socket *so)
{
	if (sb_notify(&so->so_snd))
		sowakeup(so, &so->so_snd);
}
#endif /* __APPLE__ */

/*
 * Make a copy of a sockaddr in a malloced buffer of type M_SONAME.
 */
struct sockaddr *
dup_sockaddr(struct sockaddr *sa, int canwait)
{
	struct sockaddr *sa2;

	MALLOC(sa2, struct sockaddr *, sa->sa_len, M_SONAME,
	    canwait ? M_WAITOK : M_NOWAIT);
	if (sa2)
		bcopy(sa, sa2, sa->sa_len);
	return (sa2);
}

/*
 * Create an external-format (``xsocket'') structure using the information
 * in the kernel-format socket structure pointed to by so.  This is done
 * to reduce the spew of irrelevant information over this interface,
 * to isolate user code from changes in the kernel structure, and
 * potentially to provide information-hiding if we decide that
 * some of this information should be hidden from users.
 */
void
sotoxsocket(struct socket *so, struct xsocket *xso)
{
	xso->xso_len = sizeof (*xso);
	xso->xso_so = (_XSOCKET_PTR(struct socket *))(uintptr_t)so;
	xso->so_type = so->so_type;
	xso->so_options = so->so_options;
	xso->so_linger = so->so_linger;
	xso->so_state = so->so_state;
	xso->so_pcb = (_XSOCKET_PTR(caddr_t))(uintptr_t)so->so_pcb;
	if (so->so_proto) {
		xso->xso_protocol = so->so_proto->pr_protocol;
		xso->xso_family = so->so_proto->pr_domain->dom_family;
	} else {
		xso->xso_protocol = xso->xso_family = 0;
	}
	xso->so_qlen = so->so_qlen;
	xso->so_incqlen = so->so_incqlen;
	xso->so_qlimit = so->so_qlimit;
	xso->so_timeo = so->so_timeo;
	xso->so_error = so->so_error;
	xso->so_pgid = so->so_pgid;
	xso->so_oobmark = so->so_oobmark;
	sbtoxsockbuf(&so->so_snd, &xso->so_snd);
	sbtoxsockbuf(&so->so_rcv, &xso->so_rcv);
	xso->so_uid = so->so_uid;
}


#if !CONFIG_EMBEDDED

void
sotoxsocket64(struct socket *so, struct xsocket64 *xso)
{
        xso->xso_len = sizeof (*xso);
        xso->xso_so = (u_int64_t)(uintptr_t)so;
        xso->so_type = so->so_type;
        xso->so_options = so->so_options;
        xso->so_linger = so->so_linger;
        xso->so_state = so->so_state;
        xso->so_pcb = (u_int64_t)(uintptr_t)so->so_pcb;
        if (so->so_proto) {
                xso->xso_protocol = so->so_proto->pr_protocol;
                xso->xso_family = so->so_proto->pr_domain->dom_family;
        } else {
                xso->xso_protocol = xso->xso_family = 0;
        }
        xso->so_qlen = so->so_qlen;
        xso->so_incqlen = so->so_incqlen;
        xso->so_qlimit = so->so_qlimit;
        xso->so_timeo = so->so_timeo;
        xso->so_error = so->so_error;
        xso->so_pgid = so->so_pgid;
        xso->so_oobmark = so->so_oobmark;
        sbtoxsockbuf(&so->so_snd, &xso->so_snd);
        sbtoxsockbuf(&so->so_rcv, &xso->so_rcv);
        xso->so_uid = so->so_uid;
}

#endif /* !CONFIG_EMBEDDED */

/*
 * This does the same for sockbufs.  Note that the xsockbuf structure,
 * since it is always embedded in a socket, does not include a self
 * pointer nor a length.  We make this entry point public in case
 * some other mechanism needs it.
 */
void
sbtoxsockbuf(struct sockbuf *sb, struct xsockbuf *xsb)
{
	xsb->sb_cc = sb->sb_cc;
	xsb->sb_hiwat = sb->sb_hiwat;
	xsb->sb_mbcnt = sb->sb_mbcnt;
	xsb->sb_mbmax = sb->sb_mbmax;
	xsb->sb_lowat = sb->sb_lowat;
	xsb->sb_flags = sb->sb_flags;
	xsb->sb_timeo = (short)
	    (sb->sb_timeo.tv_sec * hz) + sb->sb_timeo.tv_usec / tick;
	if (xsb->sb_timeo == 0 && sb->sb_timeo.tv_usec != 0)
		xsb->sb_timeo = 1;
}

int
soisbackground(struct socket *so)
{
	return (so->so_traffic_mgt_flags & TRAFFIC_MGT_SO_BACKGROUND);
}

#if PKT_PRIORITY
#define _MIN_NXT_CMSGHDR_PTR(cmsg)                              \
	((char *)(cmsg) +                                       \
	    __DARWIN_ALIGN32((__uint32_t)(cmsg)->cmsg_len) +    \
	    __DARWIN_ALIGN32(sizeof(struct cmsghdr)))

#define M_FIRST_CMSGHDR(m)                                                                      \
        ((char *)(m) != (char *)0L && (size_t)(m)->m_len >= sizeof(struct cmsghdr) &&           \
	  (socklen_t)(m)->m_len >= __DARWIN_ALIGN32(((struct cmsghdr *)(m)->m_data)->cmsg_len) ?\
         (struct cmsghdr *)(m)->m_data :                                                        \
         (struct cmsghdr *)0L)

#define M_NXT_CMSGHDR(m, cmsg)                                                  \
        ((char *)(cmsg) == (char *)0L ? M_FIRST_CMSGHDR(m) :                    \
            _MIN_NXT_CMSGHDR_PTR(cmsg) > ((char *)(m)->m_data) + (m)->m_len ||  \
            _MIN_NXT_CMSGHDR_PTR(cmsg) < (char *)(m)->m_data ?                  \
                (struct cmsghdr *)0L /* NULL */ :                               \
                (struct cmsghdr *)((unsigned char *)(cmsg) +                    \
                            __DARWIN_ALIGN32((__uint32_t)(cmsg)->cmsg_len)))
#endif /* PKT_PRIORITY */

__private_extern__ int
mbuf_traffic_class_from_control(struct mbuf *control)
{
#if !PKT_PRIORITY
#pragma unused(control)
	return MBUF_TC_NONE;
#else /* PKT_PRIORITY */
	struct cmsghdr *cm;
	
	for (cm = M_FIRST_CMSGHDR(control); cm; cm = M_NXT_CMSGHDR(control, cm)) {
		int tc;	

		if (cm->cmsg_len < sizeof(struct cmsghdr))
			break;
	
		if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SO_TRAFFIC_CLASS)
			continue;
		if (cm->cmsg_len != CMSG_LEN(sizeof(int)))
			continue;

		tc = *(int *)CMSG_DATA(cm);

		switch (tc) {
			case SO_TC_BE:
				return MBUF_TC_BE;
			case SO_TC_BK:
				return MBUF_TC_BK;
			case SO_TC_VI:
				return MBUF_TC_VI;
			case SO_TC_VO:
				return MBUF_TC_VO;
			default:
				break;
		}
	}
	
	return MBUF_TC_NONE;
#endif /* PKT_PRIORITY */
}

/*
 * Here is the definition of some of the basic objects in the kern.ipc
 * branch of the MIB.
 */
SYSCTL_NODE(_kern, KERN_IPC, ipc, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "IPC");

/* Check that the maximum socket buffer size is within a range */

static int
sysctl_sb_max(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	u_int32_t new_value;
	int changed = 0;
	int error = sysctl_io_number(req, sb_max, sizeof(u_int32_t), &new_value,
		&changed);
	if (!error && changed) {
		if (new_value > LOW_SB_MAX && 
			new_value <= high_sb_max ) {
			sb_max = new_value;
		} else {
			error = ERANGE;
		}
	}
	return error;
}

SYSCTL_PROC(_kern_ipc, KIPC_MAXSOCKBUF, maxsockbuf, CTLTYPE_INT | CTLFLAG_RW,
    &sb_max, 0, &sysctl_sb_max, "IU", "Maximum socket buffer size");

SYSCTL_INT(_kern_ipc, OID_AUTO, maxsockets, CTLFLAG_RD,
    &maxsockets, 0, "Maximum number of sockets avaliable");
SYSCTL_INT(_kern_ipc, KIPC_SOCKBUF_WASTE, sockbuf_waste_factor, CTLFLAG_RW,
    &sb_efficiency, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, sbspace_factor, CTLFLAG_RW,
    &sbspace_factor, 0, "Ratio of mbuf/cluster use for socket layers");
SYSCTL_INT(_kern_ipc, KIPC_NMBCLUSTERS, nmbclusters, CTLFLAG_RD,
    &nmbclusters, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, njcl, CTLFLAG_RD, &njcl, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, njclbytes, CTLFLAG_RD, &njclbytes, 0, "");
SYSCTL_INT(_kern_ipc, KIPC_SOQLIMITCOMPAT, soqlimitcompat, CTLFLAG_RW,
    &soqlimitcompat, 1, "Enable socket queue limit compatibility");
SYSCTL_INT(_kern_ipc, OID_AUTO, soqlencomp, CTLFLAG_RW,
    &soqlencomp, 0, "Listen backlog represents only complete queue");
