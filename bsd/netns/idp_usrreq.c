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
 * Copyright (c) 1984, 1985, 1986, 1987, 1993
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
 *	@(#)idp_usrreq.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/route.h>

#include <netns/ns.h>
#include <netns/ns_pcb.h>
#include <netns/ns_if.h>
#include <netns/idp.h>
#include <netns/idp_var.h>
#include <netns/ns_error.h>

/*
 * IDP protocol implementation.
 */

struct	sockaddr_ns idp_ns = { sizeof(idp_ns), AF_NS };

/*
 *  This may also be called for raw listeners.
 */
idp_input(m, nsp)
	struct mbuf *m;
	register struct nspcb *nsp;
{
	register struct idp *idp = mtod(m, struct idp *);
	struct ifnet *ifp = m->m_pkthdr.rcvif;

	if (nsp==0)
		panic("No nspcb");
	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	idp_ns.sns_addr = idp->idp_sna;
	if (ns_neteqnn(idp->idp_sna.x_net, ns_zeronet) && ifp) {
		register struct ifaddr *ifa;

		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr->sa_family == AF_NS) {
				idp_ns.sns_addr.x_net =
					IA_SNS(ifa)->sns_addr.x_net;
				break;
			}
		}
	}
	nsp->nsp_rpt = idp->idp_pt;
	if ( ! (nsp->nsp_flags & NSP_RAWIN) ) {
		m->m_len -= sizeof (struct idp);
		m->m_pkthdr.len -= sizeof (struct idp);
		m->m_data += sizeof (struct idp);
	}
	if (sbappendaddr(&nsp->nsp_socket->so_rcv, (struct sockaddr *)&idp_ns,
	    m, (struct mbuf *)0) == 0)
		goto bad;
	sorwakeup(nsp->nsp_socket);
	return;
bad:
	m_freem(m);
}

idp_abort(nsp)
	struct nspcb *nsp;
{
	struct socket *so = nsp->nsp_socket;

	ns_pcbdisconnect(nsp);
	soisdisconnected(so);
}
/*
 * Drop connection, reporting
 * the specified error.
 */
struct nspcb *
idp_drop(nsp, errno)
	register struct nspcb *nsp;
	int errno;
{
	struct socket *so = nsp->nsp_socket;

	/*
	 * someday, in the xerox world
	 * we will generate error protocol packets
	 * announcing that the socket has gone away.
	 */
	/*if (TCPS_HAVERCVDSYN(tp->t_state)) {
		tp->t_state = TCPS_CLOSED;
		(void) tcp_output(tp);
	}*/
	so->so_error = errno;
	ns_pcbdisconnect(nsp);
	soisdisconnected(so);
}

int noIdpRoute;
idp_output(nsp, m0)
	struct nspcb *nsp;
	struct mbuf *m0;
{
	register struct mbuf *m;
	register struct idp *idp;
	register struct socket *so;
	register int len = 0;
	register struct route *ro;
	struct mbuf *mprev;
	extern int idpcksum;

	/*
	 * Calculate data length.
	 */
	for (m = m0; m; m = m->m_next) {
		mprev = m;
		len += m->m_len;
	}
	/*
	 * Make sure packet is actually of even length.
	 */
	
	if (len & 1) {
		m = mprev;
		if ((m->m_flags & M_EXT) == 0 &&
			(m->m_len + m->m_data < &m->m_dat[MLEN])) {
			m->m_len++;
		} else {
			struct mbuf *m1 = m_get(M_DONTWAIT, MT_DATA);

			if (m1 == 0) {
				m_freem(m0);
				return (ENOBUFS);
			}
			m1->m_len = 1;
			* mtod(m1, char *) = 0;
			m->m_next = m1;
		}
		m0->m_pkthdr.len++;
	}

	/*
	 * Fill in mbuf with extended IDP header
	 * and addresses and length put into network format.
	 */
	m = m0;
	if (nsp->nsp_flags & NSP_RAWOUT) {
		idp = mtod(m, struct idp *);
	} else {
		M_PREPEND(m, sizeof (struct idp), M_DONTWAIT);
		if (m == 0)
			return (ENOBUFS);
		idp = mtod(m, struct idp *);
		idp->idp_tc = 0;
		idp->idp_pt = nsp->nsp_dpt;
		idp->idp_sna = nsp->nsp_laddr;
		idp->idp_dna = nsp->nsp_faddr;
		len += sizeof (struct idp);
	}

	idp->idp_len = htons((u_short)len);

	if (idpcksum) {
		idp->idp_sum = 0;
		len = ((len - 1) | 1) + 1;
		idp->idp_sum = ns_cksum(m, len);
	} else
		idp->idp_sum = 0xffff;

	/*
	 * Output datagram.
	 */
	so = nsp->nsp_socket;
	if (so->so_options & SO_DONTROUTE)
		return (ns_output(m, (struct route *)0,
		    (so->so_options & SO_BROADCAST) | NS_ROUTETOIF));
	/*
	 * Use cached route for previous datagram if
	 * possible.  If the previous net was the same
	 * and the interface was a broadcast medium, or
	 * if the previous destination was identical,
	 * then we are ok.
	 *
	 * NB: We don't handle broadcasts because that
	 *     would require 3 subroutine calls.
	 */
	ro = &nsp->nsp_route;
#ifdef ancient_history
	/*
	 * I think that this will all be handled in ns_pcbconnect!
	 */
	if (ro->ro_rt) {
		if(ns_neteq(nsp->nsp_lastdst, idp->idp_dna)) {
			/*
			 * This assumes we have no GH type routes
			 */
			if (ro->ro_rt->rt_flags & RTF_HOST) {
				if (!ns_hosteq(nsp->nsp_lastdst, idp->idp_dna))
					goto re_route;

			}
			if ((ro->ro_rt->rt_flags & RTF_GATEWAY) == 0) {
				register struct ns_addr *dst =
						&satons_addr(ro->ro_dst);
				dst->x_host = idp->idp_dna.x_host;
			}
			/* 
			 * Otherwise, we go through the same gateway
			 * and dst is already set up.
			 */
		} else {
		re_route:
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
	}
	nsp->nsp_lastdst = idp->idp_dna;
#endif /* ancient_history */
	if (noIdpRoute) ro = 0;
	return (ns_output(m, ro, so->so_options & SO_BROADCAST));
}
/* ARGSUSED */
idp_ctloutput(req, so, level, name, value)
	int req, level;
	struct socket *so;
	int name;
	struct mbuf **value;
{
	register struct mbuf *m;
	struct nspcb *nsp = sotonspcb(so);
	int mask, error = 0;
	extern long ns_pexseq;

	if (nsp == NULL)
		return (EINVAL);

	switch (req) {

	case PRCO_GETOPT:
		if (value==NULL)
			return (EINVAL);
		m = m_get(M_DONTWAIT, MT_DATA);
		if (m==NULL)
			return (ENOBUFS);
		switch (name) {

		case SO_ALL_PACKETS:
			mask = NSP_ALL_PACKETS;
			goto get_flags;

		case SO_HEADERS_ON_INPUT:
			mask = NSP_RAWIN;
			goto get_flags;
			
		case SO_HEADERS_ON_OUTPUT:
			mask = NSP_RAWOUT;
		get_flags:
			m->m_len = sizeof(short);
			*mtod(m, short *) = nsp->nsp_flags & mask;
			break;

		case SO_DEFAULT_HEADERS:
			m->m_len = sizeof(struct idp);
			{
				register struct idp *idp = mtod(m, struct idp *);
				idp->idp_len = 0;
				idp->idp_sum = 0;
				idp->idp_tc = 0;
				idp->idp_pt = nsp->nsp_dpt;
				idp->idp_dna = nsp->nsp_faddr;
				idp->idp_sna = nsp->nsp_laddr;
			}
			break;

		case SO_SEQNO:
			m->m_len = sizeof(long);
			*mtod(m, long *) = ns_pexseq++;
			break;

		default:
			error = EINVAL;
		}
		*value = m;
		break;

	case PRCO_SETOPT:
		switch (name) {
			int *ok;

		case SO_ALL_PACKETS:
			mask = NSP_ALL_PACKETS;
			goto set_head;

		case SO_HEADERS_ON_INPUT:
			mask = NSP_RAWIN;
			goto set_head;

		case SO_HEADERS_ON_OUTPUT:
			mask = NSP_RAWOUT;
		set_head:
			if (value && *value) {
				ok = mtod(*value, int *);
				if (*ok)
					nsp->nsp_flags |= mask;
				else
					nsp->nsp_flags &= ~mask;
			} else error = EINVAL;
			break;

		case SO_DEFAULT_HEADERS:
			{
				register struct idp *idp
				    = mtod(*value, struct idp *);
				nsp->nsp_dpt = idp->idp_pt;
			}
			break;
#ifdef NSIP

		case SO_NSIP_ROUTE:
			error = nsip_route(*value);
			break;
#endif /* NSIP */
		default:
			error = EINVAL;
		}
		if (value && *value)
			m_freem(*value);
		break;
	}
	return (error);
}

/*ARGSUSED*/
idp_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
	struct nspcb *nsp = sotonspcb(so);
	int error = 0;

	if (req == PRU_CONTROL)
                return (ns_control(so, (int)m, (caddr_t)nam,
			(struct ifnet *)control));
	if (control && control->m_len) {
		error = EINVAL;
		goto release;
	}
	if (nsp == NULL && req != PRU_ATTACH) {
		error = EINVAL;
		goto release;
	}
	switch (req) {

	case PRU_ATTACH:
		if (nsp != NULL) {
			error = EINVAL;
			break;
		}
		error = ns_pcballoc(so, &nspcb);
		if (error)
			break;
		error = soreserve(so, (u_long) 2048, (u_long) 2048);
		if (error)
			break;
		break;

	case PRU_DETACH:
		if (nsp == NULL) {
			error = ENOTCONN;
			break;
		}
		ns_pcbdetach(nsp);
		break;

	case PRU_BIND:
		error = ns_pcbbind(nsp, nam);
		break;

	case PRU_LISTEN:
		error = EOPNOTSUPP;
		break;

	case PRU_CONNECT:
		if (!ns_nullhost(nsp->nsp_faddr)) {
			error = EISCONN;
			break;
		}
		error = ns_pcbconnect(nsp, nam);
		if (error == 0)
			soisconnected(so);
		break;

	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	case PRU_ACCEPT:
		error = EOPNOTSUPP;
		break;

	case PRU_DISCONNECT:
		if (ns_nullhost(nsp->nsp_faddr)) {
			error = ENOTCONN;
			break;
		}
		ns_pcbdisconnect(nsp);
		soisdisconnected(so);
		break;

	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;

	case PRU_SEND:
	{
		struct ns_addr laddr;
		int s;

		if (nam) {
			laddr = nsp->nsp_laddr;
			if (!ns_nullhost(nsp->nsp_faddr)) {
				error = EISCONN;
				break;
			}
			/*
			 * Must block input while temporarily connected.
			 */
			s = splnet();
			error = ns_pcbconnect(nsp, nam);
			if (error) {
				splx(s);
				break;
			}
		} else {
			if (ns_nullhost(nsp->nsp_faddr)) {
				error = ENOTCONN;
				break;
			}
		}
		error = idp_output(nsp, m);
		m = NULL;
		if (nam) {
			ns_pcbdisconnect(nsp);
			splx(s);
			nsp->nsp_laddr.x_host = laddr.x_host;
			nsp->nsp_laddr.x_port = laddr.x_port;
		}
	}
		break;

	case PRU_ABORT:
		ns_pcbdetach(nsp);
		sofree(so);
		soisdisconnected(so);
		break;

	case PRU_SOCKADDR:
		ns_setsockaddr(nsp, nam);
		break;

	case PRU_PEERADDR:
		ns_setpeeraddr(nsp, nam);
		break;

	case PRU_SENSE:
		/*
		 * stat: don't bother with a blocksize.
		 */
		return (0);

	case PRU_SENDOOB:
	case PRU_FASTTIMO:
	case PRU_SLOWTIMO:
	case PRU_PROTORCV:
	case PRU_PROTOSEND:
		error =  EOPNOTSUPP;
		break;

	case PRU_CONTROL:
	case PRU_RCVD:
	case PRU_RCVOOB:
		return (EOPNOTSUPP);	/* do not free mbuf's */

	default:
		panic("idp_usrreq");
	}
release:
	if (control != NULL)
		m_freem(control);
	if (m != NULL)
		m_freem(m);
	return (error);
}
/*ARGSUSED*/
idp_raw_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
	int error = 0;
	struct nspcb *nsp = sotonspcb(so);
	extern struct nspcb nsrawpcb;

	switch (req) {

	case PRU_ATTACH:

		if (!(so->so_state & SS_PRIV) || (nsp != NULL)) {
			error = EINVAL;
			break;
		}
		error = ns_pcballoc(so, &nsrawpcb);
		if (error)
			break;
		error = soreserve(so, (u_long) 2048, (u_long) 2048);
		if (error)
			break;
		nsp = sotonspcb(so);
		nsp->nsp_faddr.x_host = ns_broadhost;
		nsp->nsp_flags = NSP_RAWIN | NSP_RAWOUT;
		break;
	default:
		error = idp_usrreq(so, req, m, nam, control);
	}
	return (error);
}

