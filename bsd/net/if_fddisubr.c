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
 * Copyright (c) 1995, 1996
 *	Matt Thomas <matt@3am-software.com>.  All rights reserved.
 * Copyright (c) 1982, 1989, 1993
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
 *	from: if_ethersubr.c,v 1.5 1994/12/13 22:31:45 wollman Exp
 */

#include "opt_atalk.h"
#include "opt_inet.h"
#include "opt_ipx.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#endif
#if defined(__FreeBSD__)
#include <netinet/if_fddi.h>
#else
#include <net/if_fddi.h>
#endif

#if IPX
#include <netipx/ipx.h> 
#include <netipx/ipx_if.h>
#endif

#if DECNET
#include <netdnet/dn.h>
#endif

#include "bpfilter.h"

#define senderr(e) { error = (e); goto bad;}

/*
 * This really should be defined in if_llc.h but in case it isn't.
 */
#ifndef llc_snap
#define	llc_snap	llc_un.type_snap
#endif

#if defined(__bsdi__) || defined(__NetBSD__)
#define	RTALLOC1(a, b)			rtalloc1(a, b)
#define	ARPRESOLVE(a, b, c, d, e, f)	arpresolve(a, b, c, d, e)
#elif defined(__FreeBSD__)
#define	RTALLOC1(a, b)			rtalloc1(a, b, 0UL)
#define	ARPRESOLVE(a, b, c, d, e, f)	arpresolve(a, b, c, d, e, f)
#endif
/*
 * FDDI output routine.
 * Encapsulate a packet of type family for the local net.
 * Use trailer local net encapsulation if enough data in first
 * packet leaves a multiple of 512 bytes of data in remainder.
 * Assumes that ifp is actually pointer to arpcom structure.
 */
int
fddi_output(ifp, m0, dst, rt0)
	register struct ifnet *ifp;
	struct mbuf *m0;
	struct sockaddr *dst;
	struct rtentry *rt0;
{
	u_int16_t type;
	int s, loop_copy = 0, error = 0;
 	u_char edst[6];
	register struct mbuf *m = m0;
	register struct rtentry *rt;
	register struct fddi_header *fh;
	struct arpcom *ac = (struct arpcom *)ifp;

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		senderr(ENETDOWN);
	getmicrotime(&ifp->if_lastchange);
#if !defined(__bsdi__) || _BSDI_VERSION >= 199401
	if (rt = rt0) {
		if ((rt->rt_flags & RTF_UP) == 0) {
			if (rt0 = rt = RTALLOC1(dst, 1))
				rtunref(rt);
			else 
				senderr(EHOSTUNREACH);
		}
		if (rt->rt_flags & RTF_GATEWAY) {
			if (rt->rt_gwroute == 0)
				goto lookup;
			if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
				rtfree(rt); rt = rt0;
			lookup: rt->rt_gwroute = RTALLOC1(rt->rt_gateway, 1);
				if ((rt = rt->rt_gwroute) == 0)
					senderr(EHOSTUNREACH);
			}
		}
		if (rt->rt_flags & RTF_REJECT)
			if (rt->rt_rmx.rmx_expire == 0 ||
			    time_second < rt->rt_rmx.rmx_expire)
				senderr(rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
	}
#endif
	switch (dst->sa_family) {

#if INET
	case AF_INET: {
#if !defined(__bsdi__) || _BSDI_VERSION >= 199401
		if (!ARPRESOLVE(ac, rt, m, dst, edst, rt0))
			return (0);	/* if not yet resolved */
#else
		int usetrailers;
		if (!arpresolve(ac, m, &((struct sockaddr_in *)dst)->sin_addr, edst, &usetrailers))
			return (0);	/* if not yet resolved */
#endif
		type = htons(ETHERTYPE_IP);
		break;
	}
#endif
#if IPX
	case AF_IPX:
		type = htons(ETHERTYPE_IPX);
 		bcopy((caddr_t)&(((struct sockaddr_ipx *)dst)->sipx_addr.x_host),
		    (caddr_t)edst, sizeof (edst));
		break;
#endif

#if NS
	case AF_NS:
		type = htons(ETHERTYPE_NS);
 		bcopy((caddr_t)&(((struct sockaddr_ns *)dst)->sns_addr.x_host),
		    (caddr_t)edst, sizeof (edst));
		break;
#endif
#if	ISO
	case AF_ISO: {
		int	snpalen;
		struct	llc *l;
		register struct sockaddr_dl *sdl;

		if (rt && (sdl = (struct sockaddr_dl *)rt->rt_gateway) &&
		    sdl->sdl_family == AF_LINK && sdl->sdl_alen > 0) {
			bcopy(LLADDR(sdl), (caddr_t)edst, sizeof(edst));
		} else if (error =
			    iso_snparesolve(ifp, (struct sockaddr_iso *)dst,
					    (char *)edst, &snpalen))
			goto bad; /* Not Resolved */
		/* If broadcasting on a simplex interface, loopback a copy */
		if (*edst & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		M_PREPEND(m, 3, M_DONTWAIT);
		if (m == NULL)
			return (0);
		type = 0;
		l = mtod(m, struct llc *);
		l->llc_dsap = l->llc_ssap = LLC_ISO_LSAP;
		l->llc_control = LLC_UI;
		IFDEBUG(D_ETHER)
			int i;
			printf("unoutput: sending pkt to: ");
			for (i=0; i<6; i++)
				printf("%x ", edst[i] & 0xff);
			printf("\n");
		ENDDEBUG
		} break;
#endif /* ISO */
#if	LLC
/*	case AF_NSAP: */
	case AF_CCITT: {
		register struct sockaddr_dl *sdl = 
			(struct sockaddr_dl *) rt -> rt_gateway;

		if (sdl && sdl->sdl_family != AF_LINK && sdl->sdl_alen <= 0)
			goto bad; /* Not a link interface ? Funny ... */
		bcopy(LLADDR(sdl), (char *)edst, sizeof(edst));
		if (*edst & 1)
			loop_copy = 1;
		type = 0;
#if LLC_DEBUG
		{
			int i;
			register struct llc *l = mtod(m, struct llc *);

			printf("fddi_output: sending LLC2 pkt to: ");
			for (i=0; i<6; i++)
				printf("%x ", edst[i] & 0xff);
			printf(" len 0x%x dsap 0x%x ssap 0x%x control 0x%x\n", 
			       type & 0xff, l->llc_dsap & 0xff, l->llc_ssap &0xff,
			       l->llc_control & 0xff);

		}
#endif /* LLC_DEBUG */
		} break;
#endif /* LLC */	

	case AF_UNSPEC:
	{
		struct ether_header *eh;
		loop_copy = -1;
		eh = (struct ether_header *)dst->sa_data;
 		(void)memcpy((caddr_t)edst, (caddr_t)eh->ether_dhost, sizeof (edst));
		if (*edst & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		type = eh->ether_type;
		break;
	}

#if NBPFILTER > 0
	case AF_IMPLINK:
	{
		fh = mtod(m, struct fddi_header *);
		error = EPROTONOSUPPORT;
		switch (fh->fddi_fc & (FDDIFC_C|FDDIFC_L|FDDIFC_F)) {
			case FDDIFC_LLC_ASYNC: {
				/* legal priorities are 0 through 7 */
				if ((fh->fddi_fc & FDDIFC_Z) > 7)
			        	goto bad;
				break;
			}
			case FDDIFC_LLC_SYNC: {
				/* FDDIFC_Z bits reserved, must be zero */
				if (fh->fddi_fc & FDDIFC_Z)
					goto bad;
				break;
			}
			case FDDIFC_SMT: {
				/* FDDIFC_Z bits must be non zero */
				if ((fh->fddi_fc & FDDIFC_Z) == 0)
					goto bad;
				break;
			}
			default: {
				/* anything else is too dangerous */
               	 		goto bad;
			}
		}
		error = 0;
		if (fh->fddi_dhost[0] & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		goto queue_it;
	}
#endif
	default:
		printf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
			dst->sa_family);
		senderr(EAFNOSUPPORT);
	}

	if (type != 0) {
		register struct llc *l;
		M_PREPEND(m, sizeof (struct llc), M_DONTWAIT);
		if (m == 0)
			senderr(ENOBUFS);
		l = mtod(m, struct llc *);
		l->llc_control = LLC_UI;
		l->llc_dsap = l->llc_ssap = LLC_SNAP_LSAP;
		l->llc_snap.org_code[0] = l->llc_snap.org_code[1] = l->llc_snap.org_code[2] = 0;
		(void)memcpy((caddr_t) &l->llc_snap.ether_type, (caddr_t) &type,
			sizeof(u_int16_t));
	}

	/*
	 * Add local net header.  If no space in first mbuf,
	 * allocate another.
	 */
	M_PREPEND(m, sizeof (struct fddi_header), M_DONTWAIT);
	if (m == 0)
		senderr(ENOBUFS);
	fh = mtod(m, struct fddi_header *);
	fh->fddi_fc = FDDIFC_LLC_ASYNC|FDDIFC_LLC_PRIO4;
 	(void)memcpy((caddr_t)fh->fddi_dhost, (caddr_t)edst, sizeof (edst));
  queue_it:
 	(void)memcpy((caddr_t)fh->fddi_shost, (caddr_t)ac->ac_enaddr,
	    sizeof(fh->fddi_shost));

	/*
	 * If a simplex interface, and the packet is being sent to our
	 * Ethernet address or a broadcast address, loopback a copy.
	 * XXX To make a simplex device behave exactly like a duplex
	 * device, we should copy in the case of sending to our own
	 * ethernet address (thus letting the original actually appear
	 * on the wire). However, we don't do that here for security
	 * reasons and compatibility with the original behavior.
	 */
	if ((ifp->if_flags & IFF_SIMPLEX) &&
	   (loop_copy != -1)) {
		if ((m->m_flags & M_BCAST) || loop_copy) {
			struct mbuf *n = m_copy(m, 0, (int)M_COPYALL);

			(void) if_simloop(ifp,
				n, dst, sizeof(struct fddi_header));
	     	} else if (bcmp(fh->fddi_dhost,
		    fh->fddi_shost, sizeof(fh->fddi_shost)) == 0) {
			(void) if_simloop(ifp,
				m, dst, sizeof(struct fddi_header));
			return(0);	/* XXX */
		}
	}

	s = splimp();
	/*
	 * Queue message on interface, and start output if interface
	 * not yet active.
	 */
	if (IF_QFULL(&ifp->if_snd)) {
		IF_DROP(&ifp->if_snd);
		splx(s);
		senderr(ENOBUFS);
	}
	ifp->if_obytes += m->m_pkthdr.len;
	IF_ENQUEUE(&ifp->if_snd, m);
	if ((ifp->if_flags & IFF_OACTIVE) == 0)
		(*ifp->if_start)(ifp);
	splx(s);
	if (m->m_flags & M_MCAST)
		ifp->if_omcasts++;
	return (error);

bad:
	if (m)
		m_freem(m);
	return (error);
}

/*
 * Process a received FDDI packet;
 * the packet is in the mbuf chain m without
 * the fddi header, which is provided separately.
 */
void
fddi_input(ifp, fh, m)
	struct ifnet *ifp;
	register struct fddi_header *fh;
	struct mbuf *m;
{
	register struct ifqueue *inq;
	register struct llc *l;
	int s;

	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}
	getmicrotime(&ifp->if_lastchange);
	ifp->if_ibytes += m->m_pkthdr.len + sizeof (*fh);
	if (fh->fddi_dhost[0] & 1) {
		if (bcmp((caddr_t)fddibroadcastaddr, (caddr_t)fh->fddi_dhost,
		    sizeof(fddibroadcastaddr)) == 0)
			m->m_flags |= M_BCAST;
		else
			m->m_flags |= M_MCAST;
		ifp->if_imcasts++;
	} else if ((ifp->if_flags & IFF_PROMISC)
	    && bcmp(((struct arpcom *)ifp)->ac_enaddr, (caddr_t)fh->fddi_dhost,
		    sizeof(fh->fddi_dhost)) != 0) {
		m_freem(m);
		return;
	}

#ifdef M_LINK0
	/*
	 * If this has a LLC priority of 0, then mark it so upper
	 * layers have a hint that it really came via a FDDI/Ethernet
	 * bridge.
	 */
	if ((fh->fddi_fc & FDDIFC_LLC_PRIO7) == FDDIFC_LLC_PRIO0)
		m->m_flags |= M_LINK0;
#endif

	l = mtod(m, struct llc *);
	switch (l->llc_dsap) {
#if defined(INET) || NS || IPX || defined(NETATALK)
	case LLC_SNAP_LSAP:
	{
		u_int16_t type;
		if (l->llc_control != LLC_UI || l->llc_ssap != LLC_SNAP_LSAP)
			goto dropanyway;

		if (l->llc_snap.org_code[0] != 0 || l->llc_snap.org_code[1] != 0|| l->llc_snap.org_code[2] != 0)
			goto dropanyway;
		type = ntohs(l->llc_snap.ether_type);
		m_adj(m, 8);
		switch (type) {
#if INET
		case ETHERTYPE_IP:
			if (ipflow_fastforward(m))
				return;
			schednetisr(NETISR_IP);
			inq = &ipintrq;
			break;

		case ETHERTYPE_ARP:
#if !defined(__bsdi__) || _BSDI_VERSION >= 199401
			schednetisr(NETISR_ARP);
			inq = &arpintrq;
			break;
#else
			arpinput((struct arpcom *)ifp, m);
			return;
#endif
#endif
#if IPX      
		case ETHERTYPE_IPX: 
			schednetisr(NETISR_IPX);
			inq = &ipxintrq;
			break;  
#endif   
#if NS
		case ETHERTYPE_NS:
			schednetisr(NETISR_NS);
			inq = &nsintrq;
			break;
#endif
#if DECNET
		case ETHERTYPE_DECNET:
			schednetisr(NETISR_DECNET);
			inq = &decnetintrq;
			break;
#endif

		default:
			/* printf("fddi_input: unknown protocol 0x%x\n", type); */
			ifp->if_noproto++;
			goto dropanyway;
		}
		break;
	}
#endif /* INET || NS */
#if	ISO
	case LLC_ISO_LSAP: 
		switch (l->llc_control) {
		case LLC_UI:
			/* LLC_UI_P forbidden in class 1 service */
			if ((l->llc_dsap == LLC_ISO_LSAP) &&
			    (l->llc_ssap == LLC_ISO_LSAP)) {
				/* LSAP for ISO */
				m->m_data += 3;		/* XXX */
				m->m_len -= 3;		/* XXX */
				m->m_pkthdr.len -= 3;	/* XXX */
				M_PREPEND(m, sizeof *fh, M_DONTWAIT);
				if (m == 0)
					return;
				*mtod(m, struct fddi_header *) = *fh;
				IFDEBUG(D_ETHER)
					printf("clnp packet");
				ENDDEBUG
				schednetisr(NETISR_ISO);
				inq = &clnlintrq;
				break;
			}
			goto dropanyway;
			
		case LLC_XID:
		case LLC_XID_P:
			if(m->m_len < 6)
				goto dropanyway;
			l->llc_window = 0;
			l->llc_fid = 9;
			l->llc_class = 1;
			l->llc_dsap = l->llc_ssap = 0;
			/* Fall through to */
		case LLC_TEST:
		case LLC_TEST_P:
		{
			struct sockaddr sa;
			register struct ether_header *eh;
			struct arpcom *ac = (struct arpcom *) ifp;
			int i;
			u_char c = l->llc_dsap;

			l->llc_dsap = l->llc_ssap;
			l->llc_ssap = c;
			if (m->m_flags & (M_BCAST | M_MCAST))
				bcopy((caddr_t)ac->ac_enaddr,
				      (caddr_t)eh->ether_dhost, 6);
			sa.sa_family = AF_UNSPEC;
			sa.sa_len = sizeof(sa);
			eh = (struct ether_header *)sa.sa_data;
			for (i = 0; i < 6; i++) {
				eh->ether_shost[i] = fh->fddi_dhost[i];
				eh->ether_dhost[i] = fh->fddi_shost[i];
			}
			eh->ether_type = 0;
			ifp->if_output(ifp, m, &sa, NULL);
			return;
		}
		default:
			m_freem(m);
			return;
		}
		break;
#endif /* ISO */
#if LLC
	case LLC_X25_LSAP:
	{
		M_PREPEND(m, sizeof(struct sdl_hdr) , M_DONTWAIT);
		if (m == 0)
			return;
		if ( !sdl_sethdrif(ifp, fh->fddi_shost, LLC_X25_LSAP,
				    fh->fddi_dhost, LLC_X25_LSAP, 6, 
				    mtod(m, struct sdl_hdr *)))
			panic("ETHER cons addr failure");
		mtod(m, struct sdl_hdr *)->sdlhdr_len = m->m_pkthdr.len - sizeof(struct sdl_hdr);
#if LLC_DEBUG
		printf("llc packet\n");
#endif /* LLC_DEBUG */
		schednetisr(NETISR_CCITT);
		inq = &llcintrq;
		break;
	}
#endif /* LLC */
		
	default:
		/* printf("fddi_input: unknown dsap 0x%x\n", l->llc_dsap); */
		ifp->if_noproto++;
	dropanyway:
		m_freem(m);
		return;
	}

	s = splimp();
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		m_freem(m);
	} else
		IF_ENQUEUE(inq, m);
	splx(s);
}
/*
 * Perform common duties while attaching to interface list
 */
#ifdef __NetBSD__
#define	ifa_next	ifa_list.tqe_next
#endif

void
fddi_ifattach(ifp)
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	register struct sockaddr_dl *sdl;

	ifp->if_type = IFT_FDDI;
	ifp->if_addrlen = 6;
	ifp->if_hdrlen = 21;
	ifp->if_mtu = FDDIMTU;
	ifp->if_baudrate = 100000000;
#if IFF_NOTRAILERS
	ifp->if_flags |= IFF_NOTRAILERS;
#endif
#if defined(__FreeBSD__)
	ifa = ifnet_addrs[ifp->if_index - 1];
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_FDDI;
	sdl->sdl_alen = ifp->if_addrlen;
	bcopy(((struct arpcom *)ifp)->ac_enaddr, LLADDR(sdl), ifp->if_addrlen);
#elif defined(__NetBSD__)
	LIST_INIT(&((struct arpcom *)ifp)->ac_multiaddrs);
	for (ifa = ifp->if_addrlist.tqh_first; ifa != NULL; ifa = ifa->ifa_list.tqe_next)
#else
	for (ifa = ifp->if_addrlist; ifa != NULL; ifa = ifa->ifa_next)
#endif
#if !defined(__FreeBSD__)
		if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&
		    sdl->sdl_family == AF_LINK) {
			sdl->sdl_type = IFT_FDDI;
			sdl->sdl_alen = ifp->if_addrlen;
			bcopy((caddr_t)((struct arpcom *)ifp)->ac_enaddr,
			      LLADDR(sdl), ifp->if_addrlen);
			break;
		}
#endif
}
