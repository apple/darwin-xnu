/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
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
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/ev.h>

/*
 * Primitive routines for operating on sockets and socket buffers
 */

u_long	sb_max = SB_MAX;		/* XXX should be static */

static	u_long sb_efficiency = 8;	/* parameter for sbreserve() */

char netcon[] = "netcon";

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
soisconnecting(so)
	register struct socket *so;
{

	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
}

void
soisconnected(so)
	register struct socket *so;
{	register struct kextcb *kp;
	register struct socket *head = so->so_head;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_soisconnected)
		{	if ((*kp->e_soif->sf_soisconnected)(so, kp))
				return;
		}
		kp = kp->e_next;
	}

	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;
	if (head && (so->so_state & SS_INCOMP)) {
		postevent(head,0,EV_RCONN);
		TAILQ_REMOVE(&head->so_incomp, so, so_list);
		head->so_incqlen--;
		so->so_state &= ~SS_INCOMP;
		TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		so->so_state |= SS_COMP;
		sorwakeup(head);
		wakeup((caddr_t)&head->so_timeo);
	} else {
		postevent(so,0,EV_WCONN);
		wakeup((caddr_t)&so->so_timeo);
		sorwakeup(so);
		sowwakeup(so);
	}
}

void
soisdisconnecting(so)
	register struct socket *so;
{	register struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_soisdisconnecting)
		{	if ((*kp->e_soif->sf_soisdisconnecting)(so, kp))
				return;
		}
		kp = kp->e_next;
	}

	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= (SS_ISDISCONNECTING|SS_CANTRCVMORE|SS_CANTSENDMORE);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

void
soisdisconnected(so)
	register struct socket *so;
{	register struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_soisdisconnected)
		{	if ((*kp->e_soif->sf_soisdisconnected)(so, kp))
				return;
		}
		kp = kp->e_next;
	}

	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

/*
 * Return a random connection that hasn't been serviced yet and
 * is eligible for discard.  There is a one in qlen chance that
 * we will return a null, saying that there are no dropable
 * requests.  In this case, the protocol specific code should drop
 * the new request.  This insures fairness.
 *
 * This may be used in conjunction with protocol specific queue
 * congestion routines.
 */
struct socket *
sodropablereq(head)
	register struct socket *head;
{
	register struct socket *so;
	unsigned int i, j, qlen;
	static int rnd;
	static struct timeval old_runtime;
	static unsigned int cur_cnt, old_cnt;
	struct timeval tv;

	microtime(&tv);
	if ((i = (tv.tv_sec - old_runtime.tv_sec)) != 0) {
		old_runtime = tv;
		old_cnt = cur_cnt / i;
		cur_cnt = 0;
	}

	so = TAILQ_FIRST(&head->so_incomp);
	if (!so)
		return (so);

	qlen = head->so_incqlen;
	if (++cur_cnt > qlen || old_cnt > qlen) {
		rnd = (314159 * rnd + 66329) & 0xffff;
		j = ((qlen + 1) * rnd) >> 16;

		while (j-- && so)
		    so = TAILQ_NEXT(so, so_list);
	}

	return (so);
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 */
struct socket *
sonewconn(head, connstatus)
	register struct socket *head;
	int connstatus;
{	int error = 0;
	register struct socket *so;
	register struct kextcb *kp;

	if (head->so_qlen > 3 * head->so_qlimit / 2)
		return ((struct socket *)0);
	so = soalloc(1, head->so_proto->pr_domain->dom_family, head->so_type);
	if (so == NULL)
		return ((struct socket *)0);
        
	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_sonewconn1)
		{	if ((*kp->e_soif->sf_sonewconn1)(so, connstatus, kp))
				return;
		}
		kp = kp->e_next;
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
	so->so_rcv.sb_flags |= SB_RECV;	/* XXX */
	(void) soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat);

	if (so->so_proto->pr_sfilter.tqh_first)
		error = sfilter_init(so);
	if (error == 0 && (*so->so_proto->pr_usrreqs->pru_attach)(so, 0, NULL)) {
		sfilter_term(so);
		sodealloc(so);
		return ((struct socket *)0);
	}
	so->so_proto->pr_domain->dom_refs++;

	if (connstatus) {
		TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
		so->so_state |= SS_COMP;
	} else {
		TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
		so->so_state |= SS_INCOMP;
		head->so_incqlen++;
	}
	head->so_qlen++;
	if (connstatus) {
		sorwakeup(head);
		wakeup((caddr_t)&head->so_timeo);
		so->so_state |= connstatus;
	}
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
	TAILQ_INIT(&so->so_evlist);
	return (so);
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
socantsendmore(so)
	struct socket *so;
{	register struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_socantsendmore)
		{	if ((*kp->e_soif->sf_socantsendmore)(so, kp))
				return;
		}
		kp = kp->e_next;
	}


	so->so_state |= SS_CANTSENDMORE;
	sowwakeup(so);
}

void
socantrcvmore(so)
	struct socket *so;
{	register struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_socantrcvmore)
		{	if ((*kp->e_soif->sf_socantrcvmore)(so, kp))
				return;
		}
		kp = kp->e_next;
	}


	so->so_state |= SS_CANTRCVMORE;
	sorwakeup(so);
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */
int
sbwait(sb)
	struct sockbuf *sb;
{

	sb->sb_flags |= SB_WAIT;
	return (tsleep((caddr_t)&sb->sb_cc,
	    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH, "sbwait",
	    sb->sb_timeo));
}

/*
 * Lock a sockbuf already known to be locked;
 * return any error returned from sleep (EINTR).
 */
int
sb_lock(sb)
	register struct sockbuf *sb;
{
	int error;

	while (sb->sb_flags & SB_LOCK) {
		sb->sb_flags |= SB_WANT;
		error = tsleep((caddr_t)&sb->sb_flags,
		    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK|PCATCH,
		    "sblock", 0);
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
sowakeup(so, sb)
	register struct socket *so;
	register struct sockbuf *sb;
{
	struct proc *p = current_proc();




	sb->sb_flags &= ~SB_SEL;
	selwakeup(&sb->sb_sel);

	if (sb->sb_flags & SB_WAIT) {
		sb->sb_flags &= ~SB_WAIT;
		wakeup((caddr_t)&sb->sb_cc);
	}
	if (so->so_state & SS_ASYNC) {
		if (so->so_pgid < 0)
			gsignal(-so->so_pgid, SIGIO);
		else if (so->so_pgid > 0 && (p = pfind(so->so_pgid)) != 0)
			psignal(p, SIGIO);
	}

	if (sb->sb_flags & SB_UPCALL)
		(*so->so_upcall)(so, so->so_upcallarg, M_DONTWAIT);
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

int
soreserve(so, sndcc, rcvcc)
	register struct socket *so;
	u_long sndcc, rcvcc;
{
	register struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp)
	{	if (kp->e_soif && kp->e_soif->sf_soreserve)
		{	if ((*kp->e_soif->sf_soreserve)(so, sndcc, rcvcc, kp))
				return;
		}
		kp = kp->e_next;
	}

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
	selthreadclear(&so->so_snd.sb_sel);
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
sbreserve(sb, cc)
	struct sockbuf *sb;
	u_long cc;
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
sbrelease(sb)
	struct sockbuf *sb;
{

	sbflush(sb);
	sb->sb_hiwat = sb->sb_mbmax = 0;
#if 0
	/* this is getting called with bzeroed sb in sorflush */
	{
		int oldpri = splimp();
		selthreadclear(&sb->sb_sel);
		splx(oldpri);
	}
#endif
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
void
sbappend(sb, m)
	struct sockbuf *sb;
	struct mbuf *m;
{	register struct kextcb *kp;
	register struct mbuf *n;

	if (m == 0)
		return;
	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbappend)
		{	if ((*kp->e_sout->su_sbappend)(sb, m, kp))
				return;
		}
		kp = kp->e_next;
	}

	if (n = sb->sb_mb) {
		while (n->m_nextpkt)
			n = n->m_nextpkt;
		do {
			if (n->m_flags & M_EOR) {
				sbappendrecord(sb, m); /* XXXXXX!!!! */
				return;
			}
		} while (n->m_next && (n = n->m_next));
	}
	sbcompress(sb, m, n);
}

#ifdef SOCKBUF_DEBUG
void
sbcheck(sb)
	register struct sockbuf *sb;
{
	register struct mbuf *m;
	register struct mbuf *n = 0;
	register u_long len = 0, mbcnt = 0;

	for (m = sb->sb_mb; m; m = n) {
	    n = m->m_nextpkt;
	    for (; m; m = m->m_next) {
		len += m->m_len;
		mbcnt += MSIZE;
		if (m->m_flags & M_EXT) /*XXX*/ /* pretty sure this is bogus */
			mbcnt += m->m_ext.ext_size;
		if (m->m_nextpkt)
			panic("sbcheck nextpkt");
	}
	if (len != sb->sb_cc || mbcnt != sb->sb_mbcnt) {
		printf("cc %ld != %ld || mbcnt %ld != %ld\n", len, sb->sb_cc,
		    mbcnt, sb->sb_mbcnt);
		panic("sbcheck");
	}
}
#endif

/*
 * As above, except the mbuf chain
 * begins a new record.
 */
void
sbappendrecord(sb, m0)
	register struct sockbuf *sb;
	register struct mbuf *m0;
{
	register struct mbuf *m;
	register struct kextcb *kp;
    
	if (m0 == 0)
		return;
        
	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbappendrecord)
		{	if ((*kp->e_sout->su_sbappendrecord)(sb, m0, kp))
				return;
		}
		kp = kp->e_next;
	}
    
	m = sb->sb_mb;
	if (m)
		while (m->m_nextpkt)
			m = m->m_nextpkt;
	/*
	 * Put the first mbuf on the queue.
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	if (m)
		m->m_nextpkt = m0;
	else
		sb->sb_mb = m0;
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
}

/*
 * As above except that OOB data
 * is inserted at the beginning of the sockbuf,
 * but after any other OOB data.
 */
void
sbinsertoob(sb, m0)
	register struct sockbuf *sb;
	register struct mbuf *m0;
{
	register struct mbuf *m;
	register struct mbuf **mp;
	register struct kextcb *kp;

	if (m0 == 0)
		return;
        
	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbinsertoob)
		{	if ((*kp->e_sout->su_sbinsertoob)(sb, m0, kp))
				return;
		}
		kp = kp->e_next;
	}
    
	for (mp = &sb->sb_mb; *mp ; mp = &((*mp)->m_nextpkt)) {
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
	*mp = m0;
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
}

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
int
sbappendaddr(sb, asa, m0, control)
	register struct sockbuf *sb;
	struct sockaddr *asa;
	struct mbuf *m0, *control;
{
	register struct mbuf *m, *n;
	int space = asa->sa_len;
	register struct kextcb *kp;

	if (m0 && (m0->m_flags & M_PKTHDR) == 0)
		panic("sbappendaddr");

	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbappendaddr)
		{	if ((*kp->e_sout->su_sbappendaddr)(sb, asa, m0, control, kp))
				return 0;
		}
		kp = kp->e_next;
	}

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
	for (n = m; n; n = n->m_next)
		sballoc(sb, n);
	n = sb->sb_mb;
	if (n) {
		while (n->m_nextpkt)
			n = n->m_nextpkt;
		n->m_nextpkt = m;
	} else
		sb->sb_mb = m;
	postevent(0,sb,EV_RWBYTES);
	return (1);
}

int
sbappendcontrol(sb, m0, control)
	struct sockbuf *sb;
	struct mbuf *control, *m0;
{
	register struct mbuf *m, *n;
	int space = 0;
	register struct kextcb *kp;

	if (control == 0)
		panic("sbappendcontrol");

	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbappendcontrol)
		{	if ((*kp->e_sout->su_sbappendcontrol)(sb, m0, control, kp))
				return 0;
		}
		kp = kp->e_next;
	}

	for (m = control; ; m = m->m_next) {
		space += m->m_len;
		if (m->m_next == 0)
			break;
	}
	n = m;			/* save pointer to last control buffer */
	for (m = m0; m; m = m->m_next)
		space += m->m_len;
	if (space > sbspace(sb))
		return (0);
	n->m_next = m0;			/* concatenate data to control */
	for (m = control; m; m = m->m_next)
		sballoc(sb, m);
	n = sb->sb_mb;
	if (n) {
		while (n->m_nextpkt)
			n = n->m_nextpkt;
		n->m_nextpkt = control;
	} else
		sb->sb_mb = control;
	postevent(0,sb,EV_RWBYTES);
	return (1);
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
void
sbcompress(sb, m, n)
	register struct sockbuf *sb;
	register struct mbuf *m, *n;
{
	register int eor = 0;
	register struct mbuf *o;

	while (m) {
		eor |= m->m_flags & M_EOR;
		if (m->m_len == 0 &&
		    (eor == 0 ||
		     (((o = m->m_next) || (o = n)) &&
		      o->m_type == m->m_type))) {
			m = m_free(m);
			continue;
		}
		if (n && (n->m_flags & (M_EXT | M_EOR)) == 0 &&
		    (n->m_data + n->m_len + m->m_len) < &n->m_dat[MLEN] &&
		    n->m_type == m->m_type) {
			bcopy(mtod(m, caddr_t), mtod(n, caddr_t) + n->m_len,
			    (unsigned)m->m_len);
			n->m_len += m->m_len;
			sb->sb_cc += m->m_len;
			m = m_free(m);
			continue;
		}
		if (n)
			n->m_next = m;
		else
			sb->sb_mb = m;
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
	postevent(0,sb, EV_RWBYTES);
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
void
sbflush(sb)
	register struct sockbuf *sb;
{
	register struct kextcb *kp;

	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbflush)
		{	if ((*kp->e_sout->su_sbflush)(sb, kp))
				return;
		}
		kp = kp->e_next;
	}

	if (sb->sb_flags & SB_LOCK)
		panic("sbflush: locked");
	while (sb->sb_mbcnt && sb->sb_cc)
		sbdrop(sb, (int)sb->sb_cc);
	if (sb->sb_cc || sb->sb_mb || sb->sb_mbcnt)
		panic("sbflush: cc %ld || mb %p || mbcnt %ld", sb->sb_cc, (void *)sb->sb_mb, sb->sb_mbcnt);
	postevent(0, sb, EV_RWBYTES);
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop(sb, len)
	register struct sockbuf *sb;
	register int len;
{
	register struct mbuf *m, *mn;
	struct mbuf *next;
	register struct kextcb *kp;

	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbdrop)
		{	if ((*kp->e_sout->su_sbdrop)(sb, len, kp))
				return;
		}
		kp = kp->e_next;
	}

	next = (m = sb->sb_mb) ? m->m_nextpkt : 0;
	while (len > 0) {
		if (m == 0) {
			if (next == 0)
				panic("sbdrop");
			m = next;
			next = m->m_nextpkt;
			continue;
		}
		if (m->m_len > len) {
			m->m_len -= len;
			m->m_data += len;
			sb->sb_cc -= len;
			break;
		}
		len -= m->m_len;
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	while (m && m->m_len == 0) {
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	if (m) {
		sb->sb_mb = m;
		m->m_nextpkt = next;
	} else
		sb->sb_mb = next;
	postevent(0, sb, EV_RWBYTES);
}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
void
sbdroprecord(sb)
	register struct sockbuf *sb;
{
	register struct mbuf *m, *mn;
	register struct kextcb *kp;

	kp = sotokextcb(sbtoso(sb));
	while (kp)
	{	if (kp->e_sout && kp->e_sout->su_sbdroprecord)
		{	if ((*kp->e_sout->su_sbdroprecord)(sb, kp))
				return;
		}
		kp = kp->e_next;
	}

	m = sb->sb_mb;
	if (m) {
		sb->sb_mb = m->m_nextpkt;
		do {
			sbfree(sb, m);
			MFREE(m, mn);
		} while (m = mn);
	}
	postevent(0, sb, EV_RWBYTES);
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation on a socket buffer.
 */
struct mbuf *
sbcreatecontrol(p, size, type, level)
	caddr_t p;
	register int size;
	int type, level;
{
	register struct cmsghdr *cp;
	struct mbuf *m;

	if ((m = m_get(M_DONTWAIT, MT_CONTROL)) == NULL)
		return ((struct mbuf *) NULL);
	cp = mtod(m, struct cmsghdr *);
	/* XXX check size? */
	(void)memcpy(CMSG_DATA(cp), p, size);
	size += sizeof(*cp);
	m->m_len = size;
	cp->cmsg_len = size;
	cp->cmsg_level = level;
	cp->cmsg_type = type;
	return (m);
}

/*
 * Some routines that return EOPNOTSUPP for entry points that are not
 * supported by a protocol.  Fill in as needed.
 */
int
pru_abort_notsupp(struct socket *so)
{
	return EOPNOTSUPP;
}


int
pru_accept_notsupp(struct socket *so, struct sockaddr **nam)
{
	return EOPNOTSUPP;
}

int
pru_attach_notsupp(struct socket *so, int proto, struct proc *p)
{
	return EOPNOTSUPP;
}

int
pru_bind_notsupp(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return EOPNOTSUPP;
}

int
pru_connect_notsupp(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return EOPNOTSUPP;
}

int
pru_connect2_notsupp(struct socket *so1, struct socket *so2)
{
	return EOPNOTSUPP;
}

int
pru_control_notsupp(struct socket *so, u_long cmd, caddr_t data,
		    struct ifnet *ifp, struct proc *p)
{
	return EOPNOTSUPP;
}

int
pru_detach_notsupp(struct socket *so)
{
	return EOPNOTSUPP;
}

int
pru_disconnect_notsupp(struct socket *so)
{
	return EOPNOTSUPP;
}

int
pru_listen_notsupp(struct socket *so, struct proc *p)
{
	return EOPNOTSUPP;
}

int
pru_peeraddr_notsupp(struct socket *so, struct sockaddr **nam)
{
	return EOPNOTSUPP;
}

int
pru_rcvd_notsupp(struct socket *so, int flags)
{
	return EOPNOTSUPP;
}

int
pru_rcvoob_notsupp(struct socket *so, struct mbuf *m, int flags)
{
	return EOPNOTSUPP;
}

int
pru_send_notsupp(struct socket *so, int flags, struct mbuf *m,
		 struct sockaddr *addr, struct mbuf *control,
		 struct proc *p)

{
	return EOPNOTSUPP;
}


/*
 * This isn't really a ``null'' operation, but it's the default one
 * and doesn't do anything destructive.
 */
int
pru_sense_null(struct socket *so, struct stat *sb)
{
	sb->st_blksize = so->so_snd.sb_hiwat;
	return 0;
}


int	pru_sosend_notsupp(struct socket *so, struct sockaddr *addr,
		   struct uio *uio, struct mbuf *top,
		   struct mbuf *control, int flags)

{
    return EOPNOTSUPP;
}

int	pru_soreceive_notsupp(struct socket *so, 
		      struct sockaddr **paddr,
		      struct uio *uio, struct mbuf **mp0,
		      struct mbuf **controlp, int *flagsp)
{
    return EOPNOTSUPP;
}

int

pru_shutdown_notsupp(struct socket *so)
{
	return EOPNOTSUPP;
}

int
pru_sockaddr_notsupp(struct socket *so, struct sockaddr **nam)
{
	return EOPNOTSUPP;
}

int     pru_sosend(struct socket *so, struct sockaddr *addr,
		   struct uio *uio, struct mbuf *top,
		   struct mbuf *control, int flags)
{
	return EOPNOTSUPP;
}

int     pru_soreceive(struct socket *so,
		      struct sockaddr **paddr,
		      struct uio *uio, struct mbuf **mp0,
		      struct mbuf **controlp, int *flagsp)
{
	return EOPNOTSUPP;
}


int	pru_sopoll_notsupp(struct socket *so, int events,
		   struct ucred *cred)
{
    return EOPNOTSUPP;
}



/*
 * Do we need to notify the other side when I/O is possible?
 */

int 
sb_notify(struct sockbuf *sb)
{
	return ((sb->sb_flags & (SB_WAIT|SB_SEL|SB_ASYNC|SB_UPCALL)) != 0); 
}

/*
 * How much space is there in a socket buffer (so->so_snd or so->so_rcv)?
 * This is problematical if the fields are unsigned, as the space might
 * still be negative (cc > hiwat or mbcnt > mbmax).  Should detect
 * overflow and return 0.  Should use "lmin" but it doesn't exist now.
 */
long
sbspace(struct sockbuf *sb)
{
    return ((long) imin((int)(sb->sb_hiwat - sb->sb_cc), 
	 (int)(sb->sb_mbmax - sb->sb_mbcnt)));
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
	  (so->so_proto->pr_flags&PR_CONNREQUIRED)==0)) || 
     (so->so_state & SS_CANTSENDMORE) || 
     so->so_error);
}

/* adjust counters in sb reflecting allocation of m */

void
sballoc(struct sockbuf *sb, struct mbuf *m)
{
	sb->sb_cc += m->m_len; 
	sb->sb_mbcnt += MSIZE; 
	if (m->m_flags & M_EXT) 
		sb->sb_mbcnt += m->m_ext.ext_size; 
}

/* adjust counters in sb reflecting freeing of m */
void
sbfree(struct sockbuf *sb, struct mbuf *m)
{
	sb->sb_cc -= m->m_len; 
	sb->sb_mbcnt -= MSIZE; 
	if (m->m_flags & M_EXT) 
		sb->sb_mbcnt -= m->m_ext.ext_size; 
}

/*
 * Set lock on sockbuf sb; sleep if lock is already held.
 * Unless SB_NOINTR is set on sockbuf, sleep is interruptible.
 * Returns error without lock if sleep is interrupted.
 */
int
sblock(struct sockbuf *sb, int wf)
{
	return(sb->sb_flags & SB_LOCK ? 
		((wf == M_WAIT) ? sb_lock(sb) : EWOULDBLOCK) : 
		(sb->sb_flags |= SB_LOCK), 0);
}

/* release lock on sockbuf sb */
void
sbunlock(struct sockbuf *sb)
{
	sb->sb_flags &= ~SB_LOCK; 
	if (sb->sb_flags & SB_WANT) { 
		sb->sb_flags &= ~SB_WANT; 
		wakeup((caddr_t)&(sb)->sb_flags); 
	} 
}

void
sorwakeup(struct socket * so)
{
  if (sb_notify(&so->so_rcv)) 
	sowakeup(so, &so->so_rcv); 
}

void
sowwakeup(struct socket * so)
{
  if (sb_notify(&so->so_snd)) 
	sowakeup(so, &so->so_snd); 
}

/*
 * Make a copy of a sockaddr in a malloced buffer of type M_SONAME.
 */
struct sockaddr *
dup_sockaddr(sa, canwait)
	struct sockaddr *sa;
	int canwait;
{
	struct sockaddr *sa2;

	MALLOC(sa2, struct sockaddr *, sa->sa_len, M_SONAME, 
	       canwait ? M_WAITOK : M_NOWAIT);
	if (sa2)
		bcopy(sa, sa2, sa->sa_len);
	return sa2;
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
	xso->xso_len = sizeof *xso;
	xso->xso_so = so;
	xso->so_type = so->so_type;
	xso->so_options = so->so_options;
	xso->so_linger = so->so_linger;
	xso->so_state = so->so_state;
	xso->so_pcb = so->so_pcb;
	xso->xso_protocol = so->so_proto->pr_protocol;
	xso->xso_family = so->so_proto->pr_domain->dom_family;
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
	xsb->sb_timeo = sb->sb_timeo;
}

/*
 * Here is the definition of some of the basic objects in the kern.ipc
 * branch of the MIB.
 */


SYSCTL_NODE(_kern, KERN_IPC, ipc, CTLFLAG_RW, 0, "IPC");

/* This takes the place of kern.maxsockbuf, which moved to kern.ipc. */
static int dummy;
SYSCTL_INT(_kern, KERN_DUMMY, dummy, CTLFLAG_RW, &dummy, 0, "");

SYSCTL_INT(_kern_ipc, KIPC_MAXSOCKBUF, maxsockbuf, CTLFLAG_RW, &sb_max, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, maxsockets, CTLFLAG_RD, &maxsockets, 0, "");
SYSCTL_INT(_kern_ipc, KIPC_SOCKBUF_WASTE, sockbuf_waste_factor, CTLFLAG_RW,
	   &sb_efficiency, 0, "");
SYSCTL_INT(_kern_ipc, KIPC_NMBCLUSTERS, nmbclusters, CTLFLAG_RD, &nmbclusters, 0, "");

