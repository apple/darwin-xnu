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
/*      $NetBSD: if_atmsubr.c,v 1.10 1997/03/11 23:19:51 chuck Exp $       */

/*
 *
 * Copyright (c) 1996 Charles D. Cranor and Washington University.
 * All rights reserved.
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
 *      This product includes software developed by Charles D. Cranor and 
 *	Washington University.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * if_atmsubr.c
 */

#include "opt_inet.h"
#include "opt_natm.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/errno.h>


#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_atm.h>

#include <netinet/in.h>
#include <netinet/if_atm.h>
#include <netinet/if_ether.h> /* XXX: for ETHERTYPE_* */
#if defined(INET) || defined(INET6)
#include <netinet/in_var.h>
#endif
#if NATM
#include <netnatm/natm.h>
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6	0x86dd
#endif

#define senderr(e) { error = (e); goto bad;}

/*
 * atm_output: ATM output routine
 *   inputs:
 *     "ifp" = ATM interface to output to
 *     "m0" = the packet to output
 *     "dst" = the sockaddr to send to (either IP addr, or raw VPI/VCI)
 *     "rt0" = the route to use
 *   returns: error code   [0 == ok]
 *
 *   note: special semantic: if (dst == NULL) then we assume "m" already
 *		has an atm_pseudohdr on it and just send it directly.
 *		[for native mode ATM output]   if dst is null, then
 *		rt0 must also be NULL.
 */

int
atm_output(ifp, m0, dst, rt0)
	register struct ifnet *ifp;
	struct mbuf *m0;
	struct sockaddr *dst;
	struct rtentry *rt0;
{
	u_int16_t etype = 0;			/* if using LLC/SNAP */
	int s, error = 0, sz;
	struct atm_pseudohdr atmdst, *ad;
	register struct mbuf *m = m0;
	register struct rtentry *rt;
	struct atmllc *atmllc;
	struct atmllc *llc_hdr = NULL;
	u_int32_t atm_flags;

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		senderr(ENETDOWN);

	/*
	 * check route
	 */
	if ((rt = rt0) != NULL) {

		if ((rt->rt_flags & RTF_UP) == 0) { /* route went down! */
			if ((rt0 = rt = RTALLOC1(dst, 0)) != NULL)
				rt->rt_refcnt--;
			else 
				senderr(EHOSTUNREACH);
		}

		if (rt->rt_flags & RTF_GATEWAY) {
			if (rt->rt_gwroute == 0)
				goto lookup;
			if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
				rtfree(rt); rt = rt0;
			lookup: rt->rt_gwroute = RTALLOC1(rt->rt_gateway, 0);
				if ((rt = rt->rt_gwroute) == 0)
					senderr(EHOSTUNREACH);
			}
		}

		/* XXX: put RTF_REJECT code here if doing ATMARP */

	}

	/*
	 * check for non-native ATM traffic   (dst != NULL)
	 */
	if (dst) {
		switch (dst->sa_family) {
#if defined(INET) || defined(INET6)
		case AF_INET:
		case AF_INET6:
			if (!atmresolve(rt, m, dst, &atmdst)) {
				m = NULL; 
				/* XXX: atmresolve already free'd it */
				senderr(EHOSTUNREACH);
				/* XXX: put ATMARP stuff here */
				/* XXX: watch who frees m on failure */
			}
			if (dst->sa_family == AF_INET6)
			        etype = htons(ETHERTYPE_IPV6);
			else
			        etype = htons(ETHERTYPE_IP);
			break;
#endif /* INET || INET6 */

		case AF_UNSPEC:
			/*
			 * XXX: bpfwrite or output from a pvc shadow if.
			 * assuming dst contains 12 bytes (atm pseudo
			 * header (4) + LLC/SNAP (8))
			 */
			bcopy(dst->sa_data, &atmdst, sizeof(atmdst));
			llc_hdr = (struct atmllc *)(dst->sa_data + sizeof(atmdst));
			break;
			
		default:
#if defined(__NetBSD__) || defined(__OpenBSD__)
			printf("%s: can't handle af%d\n", ifp->if_xname, 
			    dst->sa_family);
#elif defined(__FreeBSD__) || defined(__bsdi__)
			printf("%s%d: can't handle af%d\n", ifp->if_name, 
			    ifp->if_unit, dst->sa_family);
#endif
			senderr(EAFNOSUPPORT);
		}

		/*
		 * must add atm_pseudohdr to data
		 */
		sz = sizeof(atmdst);
		atm_flags = ATM_PH_FLAGS(&atmdst);
		if (atm_flags & ATM_PH_LLCSNAP) sz += 8; /* sizeof snap == 8 */
		M_PREPEND(m, sz, M_DONTWAIT);
		if (m == 0)
			senderr(ENOBUFS);
		ad = mtod(m, struct atm_pseudohdr *);
		*ad = atmdst;
		if (atm_flags & ATM_PH_LLCSNAP) {
			atmllc = (struct atmllc *)(ad + 1);
			if (llc_hdr == NULL) {
			        bcopy(ATMLLC_HDR, atmllc->llchdr, 
				      sizeof(atmllc->llchdr));
				ATM_LLC_SETTYPE(atmllc, etype); 
					/* note: already in network order */
			}
			else
			        bcopy(llc_hdr, atmllc, sizeof(struct atmllc));
		}
	}

	/*
	 * Queue message on interface, and start output if interface
	 * not yet active.
	 */
	s = splimp();
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
	return (error);

bad:
	if (m)
		m_freem(m);
	return (error);
}

/*
 * Process a received ATM packet;
 * the packet is in the mbuf chain m.
 */
void
atm_input(ifp, ah, m, rxhand)
	struct ifnet *ifp;
	register struct atm_pseudohdr *ah;
	struct mbuf *m;
	void *rxhand;
{
	register struct ifqueue *inq;
	u_int16_t etype = ETHERTYPE_IP; /* default */
	int s;

	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}
	ifp->if_ibytes += m->m_pkthdr.len;

#if ATM_PVCEXT
	if (ATM_PH_FLAGS(ah) & ATM_PH_PVCSIF) {
		/*
		 * when PVC shadow interface is used, pointer to
		 * the shadow interface is passed as rxhand.
		 * override the receive interface of the packet.
		 */
		m->m_pkthdr.rcvif = (struct ifnet *)rxhand;
		rxhand = NULL;
	}
#endif /*  ATM_PVCEXT */

	if (rxhand) {
#if NATM
		struct natmpcb *npcb = rxhand;
		s = splimp();		/* in case 2 atm cards @ diff lvls */
		npcb->npcb_inq++;	/* count # in queue */
		splx(s);
		schednetisr(NETISR_NATM);
		inq = &natmintrq;
		m->m_pkthdr.rcvif = rxhand; /* XXX: overload */
#else
		printf("atm_input: NATM detected but not configured in kernel\n");
		m_freem(m);
		return;
#endif
	} else {
		/*
		 * handle LLC/SNAP header, if present
		 */
		if (ATM_PH_FLAGS(ah) & ATM_PH_LLCSNAP) {
			struct atmllc *alc;
			if (m->m_len < sizeof(*alc) &&
			    (m = m_pullup(m, sizeof(*alc))) == 0)
				return; /* failed */
			alc = mtod(m, struct atmllc *);
			if (bcmp(alc, ATMLLC_HDR, 6)) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
				printf("%s: recv'd invalid LLC/SNAP frame [vp=%d,vc=%d]\n",
				       ifp->if_xname, ATM_PH_VPI(ah), ATM_PH_VCI(ah));
#elif defined(__FreeBSD__) || defined(__bsdi__)
				printf("%s%d: recv'd invalid LLC/SNAP frame [vp=%d,vc=%d]\n",
				       ifp->if_name, ifp->if_unit, ATM_PH_VPI(ah), ATM_PH_VCI(ah));
#endif
				m_freem(m);
				return;
			}
			etype = ATM_LLC_TYPE(alc);
			m_adj(m, sizeof(*alc));
		}

		switch (etype) {
#if INET
		case ETHERTYPE_IP:
			schednetisr(NETISR_IP);
			inq = &ipintrq;
			break;
#endif
#if INET6
		case ETHERTYPE_IPV6:
			schednetisr(NETISR_IPV6);
			inq = &ip6intrq;
			break;
#endif
		default:
			m_freem(m);
			return;
		}
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
void
atm_ifattach(ifp)
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	register struct sockaddr_dl *sdl;

	ifp->if_type = IFT_ATM;
	ifp->if_addrlen = 0;
	ifp->if_hdrlen = 0;
	ifp->if_mtu = ATMMTU;
	ifp->if_output = atm_output;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	for (ifa = ifp->if_addrlist.tqh_first; ifa != 0;
	    ifa = ifa->ifa_list.tqe_next)
#elif defined(__FreeBSD__) && (__FreeBSD__ > 2)
	for (ifa = ifp->if_addrhead.tqh_first; ifa; 
	    ifa = ifa->ifa_link.tqe_next)
#elif defined(__FreeBSD__) || defined(__bsdi__)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) 
#endif
		if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&
		    sdl->sdl_family == AF_LINK) {
			sdl->sdl_type = IFT_ATM;
			sdl->sdl_alen = ifp->if_addrlen;
#ifdef notyet /* if using ATMARP, store hardware address using the next line */
			bcopy(ifp->hw_addr, LLADDR(sdl), ifp->if_addrlen);
#endif
			break;
		}

}

#if ATM_PVCEXT
/*
 * ATM PVC shadow interface: a trick to assign a shadow interface
 * to a PVC.
 * with shadow interface, each PVC looks like an individual
 * Point-to-Point interface.
 * as oposed to the NBMA model, a shadow interface is inherently
 * multicast capable (no LANE/MARS required).
 */
struct pvcsif {
	struct ifnet sif_shadow;	/* shadow ifnet structure per pvc */
	struct atm_pseudohdr sif_aph;	/* flags + vpi:vci */
	struct ifnet *sif_ifp;		/* pointer to the genuine interface */
};

static int pvc_output __P((struct ifnet *, struct mbuf *,
			   struct sockaddr *, struct rtentry *));
static int pvc_ioctl __P((struct ifnet *, u_long, caddr_t));

/*
 * create and attach per pvc shadow interface
 * (currently detach is not supported)
 */
static int pvc_number = 0;

struct ifnet *
pvc_attach(ifp)
	struct ifnet *ifp;
{
	struct pvcsif *pvcsif;
	struct ifnet *shadow;
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	int s;

	MALLOC(pvcsif, struct pvcsif *, sizeof(struct pvcsif),
	       M_DEVBUF, M_WAITOK);
	bzero(pvcsif, sizeof(struct pvcsif));

	pvcsif->sif_ifp = ifp;
	shadow = &pvcsif->sif_shadow;

	shadow->if_name = "pvc";
	shadow->if_family = APPLE_IF_FAM_PVC;
	shadow->if_unit = pvc_number++;
	shadow->if_flags = ifp->if_flags | (IFF_POINTOPOINT | IFF_MULTICAST);
	shadow->if_ioctl = pvc_ioctl;
	shadow->if_output = pvc_output;
	shadow->if_start = NULL;
	shadow->if_mtu = ifp->if_mtu;
	shadow->if_type = ifp->if_type;
	shadow->if_addrlen = ifp->if_addrlen;
	shadow->if_hdrlen = ifp->if_hdrlen;
	shadow->if_softc = pvcsif;
	shadow->if_snd.ifq_maxlen = 50;	/* dummy */

	s = splimp();
	if_attach(shadow);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	for (ifa = shadow->if_addrlist.tqh_first; ifa != 0;
	     ifa = ifa->ifa_list.tqe_next)
#elif defined(__FreeBSD__) && (__FreeBSD__ > 2)
	for (ifa = shadow->if_addrhead.tqh_first; ifa; 
	     ifa = ifa->ifa_link.tqe_next)
#elif defined(__FreeBSD__) || defined(__bsdi__)
	for (ifa = shadow->if_addrlist; ifa; ifa = ifa->ifa_next) 
#endif
		if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&
		    sdl->sdl_family == AF_LINK) {
			sdl->sdl_type = IFT_ATM;
			sdl->sdl_alen = shadow->if_addrlen;
			break;
		}
	splx(s);

	return (shadow);
}

/*
 * pvc_output relays the packet to atm_output along with vpi:vci info.
 */
static int
pvc_output(shadow, m, dst, rt)
	struct ifnet *shadow;
	struct mbuf *m;
	struct sockaddr *dst;
	struct rtentry *rt;
{
	struct pvcsif *pvcsif;
	struct sockaddr dst_addr;
	struct atmllc *atmllc;
	u_int16_t etype = 0;
	int error = 0;

	if ((shadow->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		senderr(ENETDOWN);

	pvcsif = shadow->if_softc;
	if (ATM_PH_VCI(&pvcsif->sif_aph) == 0)
		senderr(ENETDOWN);
	
	/*
	 * create a dummy sockaddr: (using bpfwrite interface)
	 * put atm pseudo header and llc/snap into sa_data (12 bytes)
	 * and mark it as AF_UNSPEC.
	 */
	if (dst) {
		switch (dst->sa_family) {
#if defined(INET) || defined(INET6)
		case AF_INET:
		case AF_INET6:
			if (dst->sa_family == AF_INET6)
				etype = htons(ETHERTYPE_IPV6);
			else
				etype = htons(ETHERTYPE_IP);
			break;
#endif

		default:
			printf("%s%d: can't handle af%d\n", shadow->if_name, 
			       shadow->if_unit, dst->sa_family);
			senderr(EAFNOSUPPORT);
		}
	}

	dst_addr.sa_family = AF_UNSPEC;
	bcopy(&pvcsif->sif_aph, dst_addr.sa_data,
	      sizeof(struct atm_pseudohdr));
	atmllc = (struct atmllc *)
		(dst_addr.sa_data + sizeof(struct atm_pseudohdr));
	bcopy(ATMLLC_HDR, atmllc->llchdr,  sizeof(atmllc->llchdr));
	ATM_LLC_SETTYPE(atmllc, etype);  /* note: already in network order */

	return atm_output(pvcsif->sif_ifp, m, &dst_addr, rt);

bad:
	if (m)
		m_freem(m);
	return (error);
}

static int
pvc_ioctl(shadow, cmd, data)
	struct ifnet *shadow;
	u_long cmd;
	caddr_t data;
{
	struct ifnet *ifp;
	struct pvcsif *pvcsif;
	struct ifreq *ifr = (struct ifreq *) data;
	void (*ifa_rtrequest)(int, struct rtentry *, struct sockaddr *) = NULL;
	int error = 0;

	pvcsif = (struct pvcsif *)shadow->if_softc;
	ifp = pvcsif->sif_ifp;
	if (ifp == 0 || ifp->if_ioctl == 0)
		return (EOPNOTSUPP);
    
	/*
	 * pre process
	 */
	switch (cmd) {
	case SIOCGPVCSIF:
		snprintf(ifr->ifr_name, sizeof(ifr->ifr_name),
		    "%s%d", ifp->if_name, ifp->if_unit);
		return (0);

	case SIOCGPVCTX:
		do {
			struct pvctxreq *pvcreq = (struct pvctxreq *)data;

			snprintf(pvcreq->pvc_ifname,
			    sizeof(pvcreq->pvc_ifname), "%s%d",
				ifp->if_name, ifp->if_unit);
			pvcreq->pvc_aph = pvcsif->sif_aph;
		} while (0);
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0)
			return (EAFNOSUPPORT);	/* XXX */
		switch (ifr->ifr_addr.sa_family) {
#if INET
		case AF_INET:
			return (0);
#endif
#if INET6
		case AF_INET6:
			return (0);
#endif
		default:
			return (EAFNOSUPPORT);
		}
		break;
	case SIOCSIFADDR:
		if (ifp->if_flags & IFF_UP) {
			/* real if is already up */
			shadow->if_flags = ifp->if_flags |
				(IFF_POINTOPOINT|IFF_MULTICAST);
			return (0);
		}
		/*
		 * XXX: save the rtrequest field since the atm driver
		 * overwrites this field.
		 */
		ifa_rtrequest = ((struct ifaddr *)data)->ifa_rtrequest;
		break;
		
	case SIOCSIFFLAGS:
		if ((shadow->if_flags & IFF_UP) == 0) {
			/*
			 * interface down. don't pass this to
			 * the real interface.
			 */
			return (0);
		}
		if (shadow->if_flags & IFF_UP) {
			/*
			 * interface up. if the real if is already up,
			 * nothing to do.
			 */
			if (ifp->if_flags & IFF_UP) {
				shadow->if_flags = ifp->if_flags |
					(IFF_POINTOPOINT|IFF_MULTICAST);
				return (0);
			}
		}
		break;
	}

	/*
	 * pass the ioctl to the genuine interface
	 */
	error = (*ifp->if_ioctl)(ifp, cmd, data);

	/*
	 * post process
	 */
	switch (cmd) {
	case SIOCSIFMTU:
		shadow->if_mtu = ifp->if_mtu;
		break;
	case SIOCSIFADDR:
		/* restore rtrequest */
		((struct ifaddr *)data)->ifa_rtrequest = ifa_rtrequest;
		/* fall into... */
	case SIOCSIFFLAGS:
		/* update if_flags */
		shadow->if_flags = ifp->if_flags
			| (IFF_POINTOPOINT|IFF_MULTICAST);
		break;
	}

	return (error);
}

int pvc_setaph(shadow, aph)
	struct ifnet *shadow;
	struct atm_pseudohdr *aph;
{
	struct pvcsif *pvcsif;
    
	pvcsif = shadow->if_softc;
	bcopy(aph, &pvcsif->sif_aph, sizeof(struct atm_pseudohdr));
	return (0);
}

#endif /* ATM_PVCEXT */
