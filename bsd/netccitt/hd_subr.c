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
/*
 * Copyright (c) University of British Columbia, 1984
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Laboratory for Computation Vision and the Computer Science Department
 * of the University of British Columbia.
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
 *	@(#)hd_subr.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <net/if.h>

#include <netccitt/hdlc.h>
#include <netccitt/hd_var.h>
#include <netccitt/x25.h>
#include <netccitt/pk_var.h>

hd_init ()
{

	hdintrq.ifq_maxlen = IFQ_MAXLEN;
}

hd_ctlinput (prc, addr)
int	prc;
struct sockaddr *addr;
{
	register struct x25config *xcp = (struct x25config *)addr;
	register struct hdcb *hdp;
	register struct ifaddr *ifa;
	struct ifnet *ifp;
	caddr_t pk_newlink();

	if (addr->sa_family != AF_CCITT)
		return (EAFNOSUPPORT);
	if (xcp->xc_lptype != HDLCPROTO_LAPB)
		return (EPROTONOSUPPORT);
	ifa = ifa_ifwithaddr(addr);
	if (ifa == 0 || ifa->ifa_addr->sa_family != AF_CCITT ||
	    (ifp = ifa->ifa_ifp) == 0)
		panic ("hd_ctlinput");
	for (hdp = hdcbhead; hdp; hdp = hdp->hd_next)
		if (hdp->hd_ifp == ifp)
			break;

	if (hdp == 0) {		/* new interface */
		int error;
		int hd_ifoutput(), hd_output();

		/* an hdcb is now too big to fit in an mbuf */
		MALLOC(hdp, struct hdcb *, sizeof (*hdp), M_PCB, M_NOWAIT);
		if (hdp == 0)
			return (ENOBUFS);
		bzero((caddr_t)hdp, sizeof(*hdp));
		hdp->hd_pkp =
			(caddr_t) pk_newlink ((struct x25_ifaddr *) ifa, 
					      (caddr_t) hdp);
		((struct x25_ifaddr *)ifa)->ia_pkcb = 
			(struct pkcb *) hdp->hd_pkp;
		if (hdp -> hd_pkp == 0) {
			FREE(hdp, M_PCB);
			return (ENOBUFS);
		}
		hdp->hd_ifp = ifp;
		hdp->hd_ifa = ifa;
		hdp->hd_xcp = xcp;
		hdp->hd_state = INIT;
		hdp->hd_output = hd_ifoutput;
		hdp->hd_next = hdcbhead;
		hdcbhead = hdp;
	} else if (hdp->hd_pkp == 0) { /* interface got reconfigured */
		hdp->hd_pkp =
			(caddr_t) pk_newlink ((struct x25_ifaddr *) ifa, 
					      (caddr_t) hdp);
		((struct x25_ifaddr *)ifa)->ia_pkcb = 
			(struct pkcb *) hdp->hd_pkp;
		if (hdp -> hd_pkp == 0) {
			FREE(hdp, M_PCB);
			return (ENOBUFS);
		}
	}

	switch (prc) {
	case PRC_IFUP:
		if (xcp->xc_lwsize == 0 ||
			xcp->xc_lwsize > MAX_WINDOW_SIZE)
				xcp->xc_lwsize = MAX_WINDOW_SIZE;
		if (hdp->hd_state == INIT)
			SET_TIMER (hdp);
		break;

	case PRC_IFDOWN:
		if (hdp->hd_state == ABM)
			hd_message (hdp, "Operator shutdown: link closed");
		(void) pk_ctlinput (PRC_LINKDOWN, hdp->hd_pkp);

		/* fall thru to ... */

	case PRC_DISCONNECT_REQUEST:
		/* drop reference to pkcb --- it's dead meat */
		hdp->hd_pkp = (caddr_t) 0;
		((struct x25_ifaddr *)ifa)->ia_pkcb = (struct pkcb *) 0;

		hd_writeinternal (hdp, DISC, POLLON);
		hdp->hd_state = DISC_SENT;
		SET_TIMER (hdp);
	}
	return (0);
}

hd_initvars (hdp)
register struct hdcb *hdp;
{
	register struct mbuf *m;
	register int i;

	/* Clear Transmit queue. */
	while ((m = hd_remove (&hdp->hd_txq)) != NULL)
		m_freem (m);

	/* Clear Retransmit queue. */
	i = hdp->hd_lastrxnr;
	while (i != hdp->hd_retxqi) {
		m_freem (hdp->hd_retxq[i]);
		i = (i + 1) % MODULUS;
	}
	hdp->hd_retxqi = 0;

	hdp->hd_vs = hdp->hd_vr = 0;
	hdp->hd_lasttxnr = hdp->hd_lastrxnr = 0;
	hdp->hd_rrtimer = 0;
	KILL_TIMER(hdp);
	hdp->hd_retxcnt = 0;
	hdp->hd_condition = 0;
}

hd_decode (hdp, frame)
register struct hdcb *hdp;
struct Hdlc_frame *frame;
{
	register int frametype = ILLEGAL;
	register struct Hdlc_iframe *iframe = (struct Hdlc_iframe *) frame;
	register struct Hdlc_sframe *sframe = (struct Hdlc_sframe *) frame;
	register struct Hdlc_uframe *uframe = (struct Hdlc_uframe *) frame;

	if (iframe -> hdlc_0 == 0) {
		frametype = IFRAME;
		hdp->hd_iframes_in++;
	}

	else if (sframe -> hdlc_01 == 1) {
		/* Supervisory format. */
		switch (sframe -> s2) {
		case 0: 
			frametype = RR;
			hdp->hd_rrs_in++;
			break;

		case 1: 
			frametype = RNR;
			hdp->hd_rnrs_in++;
			break;

		case 2: 
			frametype = REJ;
			hdp->hd_rejs_in++;
		}
	}
	else if (uframe -> hdlc_11 == 3) {
		/* Unnumbered format. */
		switch (uframe -> m3) {
		case 0: 
			frametype = DM;
			break;

		case 1: 
			frametype = SABM;
			break;

		case 2: 
			frametype = DISC;
			break;

		case 3: 
			frametype = UA;
			break;

		case 4: 
			frametype = FRMR;
			hdp->hd_frmrs_in++;
		}
	}
	return (frametype);
}

/* 
 *  This routine is called when the HDLC layer internally  generates a
 *  command or  response  for  the remote machine ( eg. RR, UA etc. ). 
 *  Only supervisory or unnumbered frames are processed.
 */

hd_writeinternal (hdp, frametype, pf)
register struct hdcb *hdp;
register int frametype, pf;
{
	register struct mbuf *buf;
	struct Hdlc_frame *frame;
	register struct Hdlc_sframe *sframe;
	register struct Hdlc_uframe *uframe;

	MGETHDR (buf, M_DONTWAIT, MT_HEADER);
	if (buf == 0)
		return;
	frame = mtod (buf, struct Hdlc_frame *);
	sframe = mtod (buf, struct Hdlc_sframe *);
	uframe = mtod (buf, struct Hdlc_uframe *);

	/* Assume a response - address structure for DTE */
	frame -> address = ADDRESS_A;
	buf -> m_len = 2;
	buf -> m_act = buf -> m_next = NULL;

	switch (frametype) {
	case RR: 
		frame -> control = RR_CONTROL;
		hdp->hd_rrs_out++;
		break;

	case RNR: 
		frame -> control = RNR_CONTROL;
		hdp->hd_rnrs_out++;
		break;

	case REJ: 
		frame -> control = REJ_CONTROL;
		hdp->hd_rejs_out++;
		break;

	case SABM: 
		frame -> control = SABM_CONTROL;
		frame -> address = ADDRESS_B;
		break;

	case DISC: 
		if ((hdp->hd_ifp->if_flags & IFF_UP) == 0) {
			hdp->hd_state = DISCONNECTED;
			(void) m_freem (buf);
			hd_flush (hdp->hd_ifp);
			return;
		}
		frame -> control = DISC_CONTROL;
		frame -> address = ADDRESS_B;
		break;

	case DM: 
		frame -> control = DM_CONTROL;
		break;

	case UA: 
		frame -> control = UA_CONTROL;
		break;

	case FRMR: 
		frame -> control = FRMR_CONTROL;
		bcopy ((caddr_t)&hd_frmr, (caddr_t)frame -> info, 3);
		buf -> m_len = 5;
		hdp->hd_frmrs_out++;

	}

	if (sframe -> hdlc_01 == 1) {
		/* Supervisory format - RR, REJ, or RNR. */
		sframe -> nr = hdp->hd_vr;
		sframe -> pf = pf;
		hdp->hd_lasttxnr = hdp->hd_vr;
		hdp->hd_rrtimer = 0;
	}
	else
		uframe -> pf = pf;

	hd_trace (hdp, TX, frame);
	buf -> m_pkthdr.len = buf -> m_len;
	(*hdp->hd_output) (hdp, buf);
}

struct mbuf *
hd_remove (q)
struct hdtxq *q;
{
	register struct mbuf *m;

	m = q -> head;
	if (m) {
		if ((q -> head = m -> m_act) == NULL)
			q -> tail = NULL;
		m -> m_act = 0;
	}
	return (m);
}

hd_append (q, m)
register struct hdtxq *q;
register struct mbuf *m;
{

	m -> m_act = NULL;
	if (q -> tail == NULL)
		q -> head = m;
	else
		q -> tail -> m_act = m;
	q -> tail = m;
}

hd_flush (ifp)
struct ifnet *ifp;
{
	register struct mbuf *m;
	register int s;

	while (1) {
		s = splimp ();
		IF_DEQUEUE (&ifp->if_snd, m);
		splx (s);
		if (m == 0)
			break;
		m_freem (m);
	}
}

hd_message (hdp, msg)
struct hdcb *hdp;
char *msg;
{
	char *format_ntn ();

	if (hdcbhead -> hd_next)
		printf ("HDLC(%s): %s\n", format_ntn (hdp->hd_xcp), msg);
	else
		printf ("HDLC: %s\n", msg);
}

#ifdef HDLCDEBUG
hd_status (hdp)
struct hdcb *hdp;
{
	printf ("HDLC STATUS:\n V(S)=%d, V(R)=%d, retxqi=%d,\n",
		hdp->hd_vs, hdp->hd_vr, hdp->hd_retxqi);

	printf ("Last_rx_nr=%d, Last_tx_nr=%d,\n Condition=%d, Xx=%d\n",
		hdp->hd_lastrxnr, hdp->hd_lasttxnr, hdp->hd_condition, hdp->hd_xx);
}
#endif
