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
 * Copyright (C) Computer Science Department IV, 
 * 		 University of Erlangen-Nuremberg, Germany, 1992
 * Copyright (c) 1991, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by the
 * Laboratory for Computation Vision and the Computer Science Department
 * of the the University of British Columbia and the Computer Science
 * Department (IV) of the University of Erlangen-Nuremberg, Germany.
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
 *	@(#)pk_usrreq.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netccitt/x25.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>

static old_to_new();
static new_to_old();
/*
 * 
 *  X.25 Packet level protocol interface to socket abstraction.
 *
 *  Process an X.25 user request on a logical channel.  If this is a send
 *  request then m is the mbuf chain of the send data. If this is a timer
 *  expiration (called from the software clock routine) them timertype is
 *  the particular timer.
 *
 */

pk_usrreq (so, req, m, nam, control)
struct socket *so;
int req;
register struct mbuf *m, *nam;
struct mbuf *control;
{
	register struct pklcd *lcp = (struct pklcd *) so -> so_pcb;
	register int error = 0;

	if (req == PRU_CONTROL)
		return (pk_control (so, (int)m, (caddr_t)nam,
			(struct ifnet *)control));
	if (control && control -> m_len) {
		error = EINVAL;
		goto release;
	}
	if (lcp == NULL && req != PRU_ATTACH) {
		error = EINVAL;
		goto release;
	}

/*
	pk_trace (pkcbhead, TR_USER, (struct pklcd *)0,
		req, (struct x25_packet *)0);
*/

	switch (req) {
	/* 
	 *  X.25 attaches to socket via PRU_ATTACH and allocates a logical
	 *  channel descriptor.  If the socket is to  receive connections,
	 *  then the LISTEN state is entered.
	 */
	case PRU_ATTACH: 
		if (lcp) {
			error = EISCONN;
			/* Socket already connected. */
			break;
		}
		lcp = pk_attach (so);
		if (lcp == 0)
			error = ENOBUFS;
		break;

	/* 
	 *  Detach a logical channel from the socket. If the state of the
	 *  channel is embryonic, simply discard it. Otherwise we have to 
	 *  initiate a PRU_DISCONNECT which will finish later.
	 */
	case PRU_DETACH: 
		pk_disconnect (lcp);
		break;

	/* 
	 *  Give the socket an address.
	 */
	case PRU_BIND: 
		if (nam -> m_len == sizeof (struct x25_sockaddr))
			old_to_new (nam);
		error = pk_bind (lcp, nam);
		break;

	/* 
	 *  Prepare to accept connections.
	 */
	case PRU_LISTEN: 
		error = pk_listen (lcp);
		break;

	/* 
	 *  Initiate a CALL REQUEST to peer entity. Enter state SENT_CALL
	 *  and mark the socket as connecting. Set timer waiting for 
	 *  CALL ACCEPT or CLEAR.
	 */
	case PRU_CONNECT: 
		if (nam -> m_len == sizeof (struct x25_sockaddr))
			old_to_new (nam);
		if (pk_checksockaddr (nam))
			return (EINVAL);
		error = pk_connect (lcp, mtod (nam, struct sockaddr_x25 *));
		break;

	/* 
	 *  Initiate a disconnect to peer entity via a CLEAR REQUEST packet.
	 *  The socket will be disconnected when we receive a confirmation
	 *  or a clear collision.
	 */
	case PRU_DISCONNECT: 
		pk_disconnect (lcp);
		break;

	/* 
	 *  Accept an INCOMING CALL. Most of the work has already been done
	 *  by pk_input. Just return the callers address to the user.
	 */
	case PRU_ACCEPT: 
		if (lcp -> lcd_craddr == NULL)
			break;
		bcopy ((caddr_t)lcp -> lcd_craddr, mtod (nam, caddr_t),
			sizeof (struct sockaddr_x25));
		nam -> m_len = sizeof (struct sockaddr_x25);
		if (lcp -> lcd_flags & X25_OLDSOCKADDR)
			new_to_old (nam);
		break;

	/* 
	 *  After a receive, we should send a RR.
	 */
	case PRU_RCVD: 
		pk_flowcontrol (lcp, /*sbspace (&so -> so_rcv) <= */ 0, 1);
		break;

	/* 
	 *  Send INTERRUPT packet.
	 */
	case PRU_SENDOOB: 
		if (m == 0) {
			MGETHDR(m, M_WAITOK, MT_OOBDATA);
			m -> m_pkthdr.len = m -> m_len = 1;
			*mtod (m, octet *) = 0;
		}
		if (m -> m_pkthdr.len > 32) {
			m_freem (m);
			error = EMSGSIZE;
			break;
		}
		MCHTYPE(m, MT_OOBDATA);
		/* FALLTHROUGH */

	/* 
	 *  Do send by placing data on the socket output queue.
	 */
	case PRU_SEND: 
		if (control) {
			register struct cmsghdr *ch = mtod (m, struct cmsghdr *);
			control -> m_len -= sizeof (*ch);
			control -> m_data += sizeof (*ch);
			error = pk_ctloutput (PRCO_SETOPT, so, ch -> cmsg_level,
					ch -> cmsg_type, &control);
		}
		if (error == 0 && m)
			error = pk_send (lcp, m);
		break;

	/* 
	 *  Abort a virtual circuit. For example all completed calls
	 *  waiting acceptance.
	 */
	case PRU_ABORT: 
		pk_disconnect (lcp);
		break;

	/* Begin unimplemented hooks. */

	case PRU_SHUTDOWN: 
		error = EOPNOTSUPP;
		break;

	case PRU_CONTROL: 
		error = EOPNOTSUPP;
		break;

	case PRU_SENSE: 
#ifdef BSD4_3
		((struct stat *)m) -> st_blksize = so -> so_snd.sb_hiwat;
#else
		error = EOPNOTSUPP;
#endif
		break;

	/* End unimplemented hooks. */

	case PRU_SOCKADDR: 
		if (lcp -> lcd_ceaddr == 0)
			return (EADDRNOTAVAIL);
		nam -> m_len = sizeof (struct sockaddr_x25);
		bcopy ((caddr_t)lcp -> lcd_ceaddr, mtod (nam, caddr_t),
			sizeof (struct sockaddr_x25));
		if (lcp -> lcd_flags & X25_OLDSOCKADDR)
			new_to_old (nam);
		break;

	case PRU_PEERADDR:
		if (lcp -> lcd_state != DATA_TRANSFER)
			return (ENOTCONN);
		nam -> m_len = sizeof (struct sockaddr_x25);
		bcopy (lcp -> lcd_craddr ? (caddr_t)lcp -> lcd_craddr :
			(caddr_t)lcp -> lcd_ceaddr,
			mtod (nam, caddr_t), sizeof (struct sockaddr_x25));
		if (lcp -> lcd_flags & X25_OLDSOCKADDR)
			new_to_old (nam);
		break;

	/* 
	 *  Receive INTERRUPT packet.
	 */
	case PRU_RCVOOB: 
		if (so -> so_options & SO_OOBINLINE) {
			register struct mbuf *n  = so -> so_rcv.sb_mb;
			if (n && n -> m_type == MT_OOBDATA) {
				unsigned len =  n -> m_pkthdr.len;
				so -> so_rcv.sb_mb = n -> m_nextpkt;
				if (len !=  n -> m_len &&
				    (n = m_pullup (n, len)) == 0)
					break;
				m -> m_len = len;
				bcopy (mtod (m, caddr_t), mtod (n, caddr_t), len);
				m_freem (n);
			}
			break;
		}
		m -> m_len = 1;
		*mtod (m, char *) = lcp -> lcd_intrdata;
		break;

	default: 
		panic ("pk_usrreq");
	}
release:
	if (control != NULL)
		m_freem (control);
	return (error);
}

/* 
 * If you want to use UBC X.25 level 3 in conjunction with some
 * other X.25 level 2 driver, have the ifp -> if_ioctl routine
 * assign pk_start to ia -> ia_start when called with SIOCSIFCONF_X25.
 */
/* ARGSUSED */
pk_start (lcp)
register struct pklcd *lcp;
{
	pk_output (lcp);
	return (0); /* XXX pk_output should return a value */
}

#ifndef _offsetof
#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
#endif
struct sockaddr_x25 pk_sockmask = {
	_offsetof(struct sockaddr_x25, x25_addr[0]),      /* x25_len */
	0,                                                /* x25_family */
	-1,                                               /* x25_net id */
};

/*ARGSUSED*/
pk_control (so, cmd, data, ifp)
struct socket *so;
int cmd;
caddr_t data;
register struct ifnet *ifp;
{
	register struct ifreq_x25 *ifr = (struct ifreq_x25 *)data;
	register struct ifaddr *ifa = 0;
	register struct x25_ifaddr *ia = 0;
	struct pklcd *dev_lcp = 0;
	int error, s, old_maxlcn;
	unsigned n;

	/*
	 * Find address for this interface, if it exists.
	 */
	if (ifp)
		for (ifa = ifp -> if_addrlist; ifa; ifa = ifa -> ifa_next)
			if (ifa -> ifa_addr -> sa_family == AF_CCITT)
				break;

	ia = (struct x25_ifaddr *)ifa;
	switch (cmd) {
	case SIOCGIFCONF_X25:
		if (ifa == 0)
			return (EADDRNOTAVAIL);
		ifr -> ifr_xc = ia -> ia_xc;
		return (0);

	case SIOCSIFCONF_X25:
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
		if (ifp == 0)
			panic ("pk_control");
		if (ifa == (struct ifaddr *)0) {
			register struct mbuf *m;

			MALLOC(ia, struct x25_ifaddr *, sizeof (*ia),
				M_IFADDR, M_WAITOK);
			if (ia == 0)
				return (ENOBUFS);
			bzero ((caddr_t)ia, sizeof (*ia));
			if (ifa = ifp -> if_addrlist) {
				for ( ; ifa -> ifa_next; ifa = ifa -> ifa_next)
					;
				ifa -> ifa_next = &ia -> ia_ifa;
			} else
				ifp -> if_addrlist = &ia -> ia_ifa;
			ifa = &ia -> ia_ifa;
			ifa -> ifa_netmask = (struct sockaddr *)&pk_sockmask;
			ifa -> ifa_addr = (struct sockaddr *)&ia -> ia_xc.xc_addr;
			ifa -> ifa_dstaddr = (struct sockaddr *)&ia -> ia_dstaddr; /* XXX */
			ia -> ia_ifp = ifp;
			ia -> ia_dstaddr.x25_family = AF_CCITT;
			ia -> ia_dstaddr.x25_len = pk_sockmask.x25_len;
		} else if (ISISO8802(ifp) == 0) {
			rtinit (ifa, (int)RTM_DELETE, 0);
		}
		old_maxlcn = ia -> ia_maxlcn;
		ia -> ia_xc = ifr -> ifr_xc;
		ia -> ia_dstaddr.x25_net = ia -> ia_xc.xc_addr.x25_net;
		if (ia -> ia_maxlcn != old_maxlcn && old_maxlcn != 0) {
			/* VERY messy XXX */
			register struct pkcb *pkp;
			FOR_ALL_PKCBS(pkp)
				if (pkp -> pk_ia == ia)
					pk_resize (pkp);
		}
		/*
		 * Give the interface a chance to initialize if this
p		 * is its first address, and to validate the address.
		 */
		ia -> ia_start = pk_start;
		s = splimp();
		if (ifp -> if_ioctl)
			error = (*ifp -> if_ioctl)(ifp, SIOCSIFCONF_X25, 
						   (caddr_t) ifa);
		if (error)
			ifp -> if_flags &= ~IFF_UP;
		else if (ISISO8802(ifp) == 0)
			error = rtinit (ifa, (int)RTM_ADD, RTF_UP);
		splx (s);
		return (error);

	default:
		if (ifp == 0 || ifp -> if_ioctl == 0)
			return (EOPNOTSUPP);
		return ((*ifp -> if_ioctl)(ifp, cmd, data));
	}
}

pk_ctloutput (cmd, so, level, optname, mp)
struct socket *so;
struct mbuf **mp;
int cmd, level, optname;
{
	register struct mbuf *m = *mp;
	register struct pklcd *lcp = (struct pklcd *) so -> so_pcb;
	int error = EOPNOTSUPP;

	if (m == 0)
		return (EINVAL);
	if (cmd == PRCO_SETOPT) switch (optname) {
	case PK_FACILITIES:
		if (m == 0)
			return (EINVAL);
		lcp -> lcd_facilities = m;
		*mp = 0;
		return (0);

	case PK_ACCTFILE:
		if ((so->so_state & SS_PRIV) == 0)
			error = EPERM;
		else if (m -> m_len)
			error = pk_accton (mtod (m, char *));
		else
			error = pk_accton ((char *)0);
		break;

	case PK_RTATTACH:
		error = pk_rtattach (so, m);
		break;
	    
	case PK_PRLISTEN:
		error = pk_user_protolisten (mtod (m, u_char *));
	}
	if (*mp) {
		(void) m_freem (*mp);
		*mp = 0;
	}
	return (error);

}


/*
 * Do an in-place conversion of an "old style"
 * socket address to the new style
 */

static
old_to_new (m)
register struct mbuf *m;
{
	register struct x25_sockaddr *oldp;
	register struct sockaddr_x25 *newp;
	register char *ocp, *ncp;
	struct sockaddr_x25 new;

	oldp = mtod (m, struct x25_sockaddr *);
	newp = &new;
	bzero ((caddr_t)newp, sizeof (*newp));

	newp -> x25_family = AF_CCITT;
	newp -> x25_len = sizeof(*newp);
	newp -> x25_opts.op_flags = (oldp -> xaddr_facilities & X25_REVERSE_CHARGE)
		| X25_MQBIT | X25_OLDSOCKADDR;
	if (oldp -> xaddr_facilities & XS_HIPRIO)	/* Datapac specific */
		newp -> x25_opts.op_psize = X25_PS128;
	bcopy ((caddr_t)oldp -> xaddr_addr, newp -> x25_addr,
	       (unsigned)min (oldp -> xaddr_len, sizeof (newp -> x25_addr) - 1));
	if (bcmp ((caddr_t)oldp -> xaddr_proto, newp -> x25_udata, 4) != 0) {
		bcopy ((caddr_t)oldp -> xaddr_proto, newp -> x25_udata, 4);
		newp -> x25_udlen = 4;
	}
	ocp = (caddr_t)oldp -> xaddr_userdata;
	ncp = newp -> x25_udata + 4;
	while (*ocp && ocp < (caddr_t)oldp -> xaddr_userdata + 12) {
		if (newp -> x25_udlen == 0)
			newp -> x25_udlen = 4;
		*ncp++ = *ocp++;
		newp -> x25_udlen++;
	}
	bcopy ((caddr_t)newp, mtod (m, char *), sizeof (*newp));
	m -> m_len = sizeof (*newp);
}

/*
 * Do an in-place conversion of a new style
 * socket address to the old style
 */

static
new_to_old (m)
register struct mbuf *m;
{
	register struct x25_sockaddr *oldp;
	register struct sockaddr_x25 *newp;
	register char *ocp, *ncp;
	struct x25_sockaddr old;

	oldp = &old;
	newp = mtod (m, struct sockaddr_x25 *);
	bzero ((caddr_t)oldp, sizeof (*oldp));

	oldp -> xaddr_facilities = newp -> x25_opts.op_flags & X25_REVERSE_CHARGE;
	if (newp -> x25_opts.op_psize == X25_PS128)
		oldp -> xaddr_facilities |= XS_HIPRIO;	/* Datapac specific */
	ocp = (char *)oldp -> xaddr_addr;
	ncp = newp -> x25_addr;
	while (*ncp) {
		*ocp++ = *ncp++;
		oldp -> xaddr_len++;
	}

	bcopy (newp -> x25_udata, (caddr_t)oldp -> xaddr_proto, 4);
	if (newp -> x25_udlen > 4)
		bcopy (newp -> x25_udata + 4, (caddr_t)oldp -> xaddr_userdata,
			(unsigned)(newp -> x25_udlen - 4));

	bcopy ((caddr_t)oldp, mtod (m, char *), sizeof (*oldp));
	m -> m_len = sizeof (*oldp);
}


pk_checksockaddr (m)
struct mbuf *m;
{
	register struct sockaddr_x25 *sa = mtod (m, struct sockaddr_x25 *);
	register char *cp;

	if (m -> m_len != sizeof (struct sockaddr_x25))
		return (1);
	if (sa -> x25_family != AF_CCITT ||
		sa -> x25_udlen > sizeof (sa -> x25_udata))
		return (1);
	for (cp = sa -> x25_addr; *cp; cp++) {
		if (*cp < '0' || *cp > '9' ||
			cp >= &sa -> x25_addr[sizeof (sa -> x25_addr) - 1])
			return (1);
	}
	return (0);
}

pk_send (lcp, m)
struct pklcd *lcp;
register struct mbuf *m;
{
	int mqbit = 0, error = 0;
	register struct x25_packet *xp;
	register struct socket *so;

	if (m -> m_type == MT_OOBDATA) {
		if (lcp -> lcd_intrconf_pending)
			error = ETOOMANYREFS;
		if (m -> m_pkthdr.len > 32)
			error = EMSGSIZE;
		M_PREPEND(m, PKHEADERLN, M_WAITOK);
		if (m == 0 || error)
			goto bad;
		*(mtod (m, octet *)) = 0;
		xp = mtod (m, struct x25_packet *);
		X25SBITS(xp -> bits, fmt_identifier, 1);
		xp -> packet_type = X25_INTERRUPT;
		SET_LCN(xp, lcp -> lcd_lcn);
		sbinsertoob ( (so = lcp -> lcd_so) ?
			&so -> so_snd : &lcp -> lcd_sb, m);
		goto send;
	}
	/*
	 * Application has elected (at call setup time) to prepend
	 * a control byte to each packet written indicating m-bit
	 * and q-bit status.  Examine and then discard this byte.
	 */
	if (lcp -> lcd_flags & X25_MQBIT) {
		if (m -> m_len < 1) {
			m_freem (m);
			return (EMSGSIZE);
		}
		mqbit = *(mtod (m, u_char *));
		m -> m_len--;
		m -> m_data++;
		m -> m_pkthdr.len--;
	}
	error = pk_fragment (lcp, m, mqbit & 0x80, mqbit & 0x40, 1);
send:
	if (error == 0 && lcp -> lcd_state == DATA_TRANSFER)
		lcp -> lcd_send (lcp); /* XXXXXXXXX fix pk_output!!! */
	return (error);
bad:
	if (m)
		m_freem (m);
	return (error);
}
