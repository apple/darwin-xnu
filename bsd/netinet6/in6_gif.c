/*	$KAME: in6_gif.c,v 1.27 2000/03/25 07:23:43 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * in6_gif.c
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#if !defined(__FreeBSD__) || __FreeBSD__ < 3
#include <sys/ioctl.h>
#endif
#include <sys/malloc.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#if INET
#include <netinet/ip.h>
#endif
#include <netinet/ip_encap.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_gif.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6protosw.h>
#endif
#include <netinet/ip_ecn.h>

#include <net/if_gif.h>

#include <net/net_osdep.h>

#if INET6
extern struct ip6protosw in6_gif_protosw;
#endif

int
in6_gif_output(ifp, family, m, rt)
	struct ifnet *ifp;
	int family; /* family of the packet to be encapsulate. */
	struct mbuf *m;
	struct rtentry *rt;
{
	struct gif_softc *sc = (struct gif_softc*)ifp;
	struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sc->gif_ro6.ro_dst;
	struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)sc->gif_psrc;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *)sc->gif_pdst;
	struct ip6_hdr *ip6;
	int proto;
	u_int8_t itos, otos;

	if (sin6_src == NULL || sin6_dst == NULL ||
	    sin6_src->sin6_family != AF_INET6 ||
	    sin6_dst->sin6_family != AF_INET6) {
		m_freem(m);
		return EAFNOSUPPORT;
	}

	switch (family) {
#if INET
	case AF_INET:
	    {
		struct ip *ip;

		proto = IPPROTO_IPV4;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return ENOBUFS;
		}
		ip = mtod(m, struct ip *);
		itos = ip->ip_tos;
		break;
	    }
#endif
#if INET6
	case AF_INET6:
	    {
		struct ip6_hdr *ip6;
		proto = IPPROTO_IPV6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return ENOBUFS;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		break;
	    }
#endif
	default:
#if DEBUG
		printf("in6_gif_output: warning: unknown family %d passed\n",
			family);
#endif
		m_freem(m);
		return EAFNOSUPPORT;
	}
	
	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
		printf("ENOBUFS in in6_gif_output %d\n", __LINE__);
		return ENOBUFS;
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)m->m_pkthdr.len);
	ip6->ip6_nxt	= proto;
	ip6->ip6_hlim	= ip6_gif_hlim;
	ip6->ip6_src	= sin6_src->sin6_addr;
	if (ifp->if_flags & IFF_LINK0) {
		/* multi-destination mode */
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
			ip6->ip6_dst = sin6_dst->sin6_addr;
		else if (rt) {
			if (family != AF_INET6) {
				m_freem(m);
				return EINVAL;	/*XXX*/
			}
			ip6->ip6_dst = ((struct sockaddr_in6 *)(rt->rt_gateway))->sin6_addr;
		} else {
			m_freem(m);
			return ENETUNREACH;
		}
	} else {
		/* bidirectional configured tunnel mode */
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
			ip6->ip6_dst = sin6_dst->sin6_addr;
		else  {
			m_freem(m);
			return ENETUNREACH;
		}
	}
	if (ifp->if_flags & IFF_LINK1) {
		otos = 0;
		ip_ecn_ingress(ECN_ALLOWED, &otos, &itos);
		ip6->ip6_flow |= htonl((u_int32_t)otos << 20);
	}

	if (dst->sin6_family != sin6_dst->sin6_family ||
	     !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &sin6_dst->sin6_addr)) {
		/* cache route doesn't match */
		bzero(dst, sizeof(*dst));
		dst->sin6_family = sin6_dst->sin6_family;
		dst->sin6_len = sizeof(struct sockaddr_in6);
		dst->sin6_addr = sin6_dst->sin6_addr;
		if (sc->gif_ro6.ro_rt) {
			RTFREE(sc->gif_ro6.ro_rt);
			sc->gif_ro6.ro_rt = NULL;
		}
#if 0
		sc->gif_if.if_mtu = GIF_MTU;
#endif
	}

	if (sc->gif_ro6.ro_rt == NULL) {
		rtalloc((struct route *)&sc->gif_ro6);
		if (sc->gif_ro6.ro_rt == NULL) {
			m_freem(m);
			return ENETUNREACH;
		}
#if 0
		ifp->if_mtu = sc->gif_ro6.ro_rt->rt_ifp->if_mtu
			- sizeof(struct ip6_hdr);
#endif
	}
	
	return(ip6_output(m, 0, &sc->gif_ro6, 0, 0, NULL));
}

int in6_gif_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
#if 0
	struct gif_softc *sc;
#endif
	struct ifnet *gifp = NULL;
	struct ip6_hdr *ip6;
#if 0
	int i;
#endif
	int af = 0;
	u_int32_t otos;

	ip6 = mtod(m, struct ip6_hdr *);

#if 0
#define satoin6(sa)	(((struct sockaddr_in6 *)(sa))->sin6_addr)
	for (i = 0, sc = gif; i < ngif; i++, sc++) {
		if (sc->gif_psrc == NULL ||
		    sc->gif_pdst == NULL ||
		    sc->gif_psrc->sa_family != AF_INET6 ||
		    sc->gif_pdst->sa_family != AF_INET6) {
			continue;
		}
		if ((sc->gif_if.if_flags & IFF_UP) == 0)
			continue;
		if ((sc->gif_if.if_flags & IFF_LINK0) &&
		    IN6_ARE_ADDR_EQUAL(&satoin6(sc->gif_psrc), &ip6->ip6_dst) &&
		    IN6_IS_ADDR_UNSPECIFIED(&satoin6(sc->gif_pdst))) {
			gifp = &sc->gif_if;
			continue;
		}
		if (IN6_ARE_ADDR_EQUAL(&satoin6(sc->gif_psrc), &ip6->ip6_dst) &&
		    IN6_ARE_ADDR_EQUAL(&satoin6(sc->gif_pdst), &ip6->ip6_src)) {
			gifp = &sc->gif_if;
			break;
		}
	}
#else
	gifp = (struct ifnet *)encap_getarg(m);
#endif

	if (gifp == NULL) {
		m_freem(m);
		ip6stat.ip6s_nogif++;
		return IPPROTO_DONE;
	}

	if ((gifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ip6stat.ip6s_nogif++;
		return IPPROTO_DONE;
	}

	otos = ip6->ip6_flow;
	m_adj(m, *offp);

	switch (proto) {
#if INET
	case IPPROTO_IPV4:
	    {
		struct ip *ip;
		u_int8_t otos8;
		af = AF_INET;
		otos8 = (ntohl(otos) >> 20) & 0xff;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return IPPROTO_DONE;
		}
		ip = mtod(m, struct ip *);
		if (gifp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos8, &ip->ip_tos);
		break;
	    }
#endif /* INET */
#if INET6
	case IPPROTO_IPV6:
	    {
		struct ip6_hdr *ip6;
		af = AF_INET6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return IPPROTO_DONE;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		if (gifp->if_flags & IFF_LINK1)
			ip6_ecn_egress(ECN_ALLOWED, &otos, &ip6->ip6_flow);
		break;
	    }
#endif
	default:
		ip6stat.ip6s_nogif++;
		m_freem(m);
		return IPPROTO_DONE;
	}
		
	gif_input(m, af, gifp);
	return IPPROTO_DONE;
}

int
in6_gif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
	caddr_t data;
{
	struct gif_softc *sc  = (struct gif_softc*)ifp;
	struct ifreq     *ifr = (struct ifreq*)data;
	int error = 0, size;
	struct sockaddr *sa, *dst, *src;
	const struct encaptab *p;
	struct sockaddr_in6 smask6, dmask6;
		
	switch (cmd) {
	case SIOCSIFFLAGS:
		/*
		 * whenever we change our idea about multi-destination mode
		 * we need to update encap attachment.
		 */
		if (((ifp->if_flags ^ sc->gif_oflags) & IFF_LINK0) == 0)
			break;
		if (sc->gif_psrc == NULL || sc->gif_pdst == NULL ||
		    sc->gif_psrc->sa_family != sc->gif_pdst->sa_family)
			break;
		bzero(&smask6, sizeof(smask6));
		smask6.sin6_addr.s6_addr32[0] = ~0;
		smask6.sin6_addr.s6_addr32[1] = ~0;
		smask6.sin6_addr.s6_addr32[2] = ~0;
		smask6.sin6_addr.s6_addr32[3] = ~0;
#if 0	/* we'll need to do this soon */
		smask6.sin6_scope_id = ~0;
#endif
		dmask6 = smask6;
		if ((ifp->if_flags & IFF_LINK0) == 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)dst)->sin6_addr)) {
			bzero(&dmask6, sizeof(dmask6));
#if 0	/* we'll need to do this soon */
			dmask6.sin6_scope_id = ~0;
#endif
		}
		p = encap_attach(sc->gif_psrc->sa_family, -1, sc->gif_psrc,
			(struct sockaddr *)&smask6, sc->gif_pdst,
			(struct sockaddr *)&dmask6,
			(struct protosw *)&in6_gif_protosw, &sc->gif_if);
		if (p == NULL) {
			error = EINVAL;
			goto bad;
		}
		if (sc->encap_cookie != NULL)
			(void)encap_detach(sc->encap_cookie);
		sc->encap_cookie = p;
		sc->gif_oflags = ifp->if_flags;

		break;

#if INET6
	case SIOCSIFPHYADDR_IN6:
#endif
		switch (ifr->ifr_addr.sa_family) {
#if INET6
		case AF_INET6:
			src = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_dstaddr);

			bzero(&smask6, sizeof(smask6));
			smask6.sin6_addr.s6_addr32[0] = ~0;
			smask6.sin6_addr.s6_addr32[1] = ~0;
			smask6.sin6_addr.s6_addr32[2] = ~0;
			smask6.sin6_addr.s6_addr32[3] = ~0;
#if 0	/* we'll need to do this soon */
			smask6.sin6_scope_id = ~0;
#endif
			dmask6 = smask6;
			if ((ifp->if_flags & IFF_LINK0) == 0 &&
			    IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)dst)->sin6_addr)) {
				bzero(&dmask6, sizeof(dmask6));
#if 0	/* we'll need to do this soon */
				dmask6.sin6_scope_id = ~0;
#endif
			}
			size = sizeof(struct sockaddr_in6);
			break;
#endif /* INET6 */
		default:
			error = EAFNOSUPPORT;
			goto bad;
		}

		if (sc->encap_cookie != NULL)
			(void)encap_detach(sc->encap_cookie);
		if (sc->gif_psrc != NULL) {
			_FREE((caddr_t)sc->gif_psrc, M_IFADDR);
			sc->gif_psrc = NULL;
		}
		if (sc->gif_pdst != NULL) {
			_FREE((caddr_t)sc->gif_pdst, M_IFADDR);
			sc->gif_pdst = NULL;
		}

		p = encap_attach(ifr->ifr_addr.sa_family, -1, src,
			(struct sockaddr *)&smask6, dst,
			(struct sockaddr *)&dmask6,
			(struct protosw *)&in6_gif_protosw, &sc->gif_if);
		if (p == NULL) {
			error = EINVAL;
			goto bad;
		}
		sc->encap_cookie = p;
		sc->gif_oflags = ifp->if_flags;

		sa = (struct sockaddr *)_MALLOC(size, M_IFADDR, M_WAITOK);
		bcopy((caddr_t)src, (caddr_t)sa, size);
		sc->gif_psrc = sa;
		
		sa = (struct sockaddr *)_MALLOC(size, M_IFADDR, M_WAITOK);
		bcopy((caddr_t)dst, (caddr_t)sa, size);
		sc->gif_pdst = sa;
		
		ifp->if_flags |= IFF_UP;
		if_up(ifp);		/* send up RTM_IFINFO */

		error = 0;
		break;
	default:
		error = EINVAL;
		goto bad;
	}

 bad:
	return error;
}
