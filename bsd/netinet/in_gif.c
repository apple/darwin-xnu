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
/*	$KAME: in_gif.c,v 1.27 2000/03/30 01:29:05 jinmei Exp $	*/

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
 * in_gif.c
 */
#if BSD310
#include "opt_mrouting.h"
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#endif
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#ifdef __FreeBSD__
#include <sys/kernel.h>
#include <sys/sysctl.h>
#endif
#if !defined(__FreeBSD__) || __FreeBSD__ < 3
#include <sys/ioctl.h>
#endif
#include <sys/protosw.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#include <sys/malloc.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/if_gif.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_gif.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip_ecn.h>

#if INET6
#include <netinet/ip6.h>
#endif

#if MROUTING
#include <netinet/ip_mroute.h>
#endif /* MROUTING */

#include <net/if_gif.h>	

#include "gif.h"

#include <net/net_osdep.h>

#if NGIF > 0
int	ip_gif_ttl = GIF_TTL;
#else
int	ip_gif_ttl = 0;
#endif

extern struct protosw in_gif_protosw;

SYSCTL_INT(_net_inet_ip, IPCTL_GIF_TTL, gifttl,
	 CTLFLAG_RW, &ip_gif_ttl , 0, "");

int
in_gif_output(ifp, family, m, rt)
	struct ifnet	*ifp;
	int		family;
	struct mbuf	*m;
	struct rtentry *rt;
{
	register struct gif_softc *sc = (struct gif_softc*)ifp;
	struct sockaddr_in *dst = (struct sockaddr_in *)&sc->gif_ro.ro_dst;
	struct sockaddr_in *sin_src = (struct sockaddr_in *)sc->gif_psrc;
	struct sockaddr_in *sin_dst = (struct sockaddr_in *)sc->gif_pdst;
	struct ip iphdr;	/* capsule IP header, host byte ordered */
	int proto, error;
	u_int8_t tos;

	if (sin_src == NULL || sin_dst == NULL ||
	    sin_src->sin_family != AF_INET ||
	    sin_dst->sin_family != AF_INET) {
		printf("in_gif_output: unknown family src=%x dst=%x\n", sin_src->sin_family, sin_dst->sin_family);
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
		tos = ip->ip_tos;
		break;
	    }
#endif /*INET*/
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
		tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		break;
	    }
#endif /*INET6*/
	default:
#if DEBUG
		printf("in_gif_output: warning: unknown family %d passed\n",
			family);
#endif
		m_freem(m);
		return EAFNOSUPPORT;
	}

	bzero(&iphdr, sizeof(iphdr));
	iphdr.ip_src = sin_src->sin_addr;
	if (ifp->if_flags & IFF_LINK0) {
		/* multi-destination mode */
		if (sin_dst->sin_addr.s_addr != INADDR_ANY)
			iphdr.ip_dst = sin_dst->sin_addr;
		else if (rt) {
			if (family != AF_INET) {
				m_freem(m);
				return EINVAL;	/*XXX*/
			}
			iphdr.ip_dst = ((struct sockaddr_in *)
					(rt->rt_gateway))->sin_addr;
		} else {
			m_freem(m);
			return ENETUNREACH;
		}
	} else {
		/* bidirectional configured tunnel mode */
		if (sin_dst->sin_addr.s_addr != INADDR_ANY)
			iphdr.ip_dst = sin_dst->sin_addr;
		else {
			m_freem(m);
			return ENETUNREACH;
		}
	}
	iphdr.ip_p = proto;
	/* version will be set in ip_output() */
	iphdr.ip_ttl = ip_gif_ttl;
	iphdr.ip_len = m->m_pkthdr.len + sizeof(struct ip);
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &iphdr.ip_tos, &tos);

	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL) {
		printf("ENOBUFS in in_gif_output %d\n", __LINE__);
		return ENOBUFS;
	}

	*(mtod(m, struct ip *)) = iphdr;

	if (dst->sin_family != sin_dst->sin_family ||
	    dst->sin_addr.s_addr != sin_dst->sin_addr.s_addr) {
		/* cache route doesn't match */
		dst->sin_family = sin_dst->sin_family;
		dst->sin_len = sizeof(struct sockaddr_in);
		dst->sin_addr = sin_dst->sin_addr;
		if (sc->gif_ro.ro_rt) {
			RTFREE(sc->gif_ro.ro_rt);
			sc->gif_ro.ro_rt = NULL;
		}
#if 0
		sc->gif_if.if_mtu = GIF_MTU;
#endif
	}

	if (sc->gif_ro.ro_rt == NULL) {
		rtalloc(&sc->gif_ro);
		if (sc->gif_ro.ro_rt == NULL) {
			m_freem(m);
			return ENETUNREACH;
		}
#if 0
		ifp->if_mtu = sc->gif_ro.ro_rt->rt_ifp->if_mtu
			- sizeof(struct ip);
#endif
	}

#ifndef __OpenBSD__
	error = ip_output(m, NULL, &sc->gif_ro, 0, NULL);
#else
	error = ip_output(m, NULL, &sc->gif_ro, 0, NULL, NULL);
#endif
	return(error);
}

void
in_gif_input(m, off)
	struct mbuf *m;
	int off;
{
	struct gif_softc *sc;
	struct ifnet *gifp = NULL;
	struct ip *ip;
	int i, af, proto;
	u_int8_t otos;

	if (gif == NULL) {
		m_freem(m);
		return; 
	}

	ip = mtod(m, struct ip *);
        proto = ip->ip_p;

#if 0
	/* this code will be soon improved. */
#define	satosin(sa)	((struct sockaddr_in *)(sa))	
	for (i = 0, sc = gif; i < ngif; i++, sc++) {
		if (sc->gif_psrc == NULL
		 || sc->gif_pdst == NULL
		 || sc->gif_psrc->sa_family != AF_INET
		 || sc->gif_pdst->sa_family != AF_INET) {
			continue;
		}

		if ((sc->gif_if.if_flags & IFF_UP) == 0)
			continue;

		if ((sc->gif_if.if_flags & IFF_LINK0)
		 && satosin(sc->gif_psrc)->sin_addr.s_addr == ip->ip_dst.s_addr
		 && satosin(sc->gif_pdst)->sin_addr.s_addr == INADDR_ANY) {
			gifp = &sc->gif_if;
			continue;
		}

		if (satosin(sc->gif_psrc)->sin_addr.s_addr == ip->ip_dst.s_addr
		 && satosin(sc->gif_pdst)->sin_addr.s_addr == ip->ip_src.s_addr)
		{
			gifp = &sc->gif_if;
			break;
		}
	}
#else
	gifp = (struct ifnet *)encap_getarg(m);
#endif

	if (gifp == NULL) {
		/* for backward compatibility */
		if (proto == IPPROTO_IPV4) {
#ifdef __OpenBSD__
#if defined(MROUTING) || defined(IPSEC)
			ip4_input(m, off, proto);
			return;
#endif
#else
#if MROUTING
			ipip_input(m, off);
			return;
#endif /*MROUTING*/
#endif
		}
		m_freem(m);
		ipstat.ips_nogif++;
		return;
	}

	if ((gifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ipstat.ips_nogif++;
		return;
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	switch (proto) {
#if INET
	case IPPROTO_IPV4:
	    {
		struct ip *ip;
		af = AF_INET;
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return;
		}
		ip = mtod(m, struct ip *);
		if (gifp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &ip->ip_tos);
		break;
	    }
#endif
#if INET6
	case IPPROTO_IPV6:
	    {
		struct ip6_hdr *ip6;
		u_int8_t itos;
		af = AF_INET6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		if (gifp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
		ip6->ip6_flow &= ~htonl(0xff << 20);
		ip6->ip6_flow |= htonl((u_int32_t)itos << 20);
		break;
	    }
#endif /* INET6 */
	default:
		ipstat.ips_nogif++;
		m_freem(m);
		return;
	}
	gif_input(m, af, gifp);
	return;
}

int
in_gif_ioctl(ifp, cmd, data)
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
	struct sockaddr_in smask4, dmask4;
		
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
		bzero(&smask4, sizeof(smask4));
		smask4.sin_addr.s_addr = ~0;
		dmask4 = smask4;
		if ((ifp->if_flags & IFF_LINK0) != 0 &&
		    ((struct sockaddr_in *)dst)->sin_addr.s_addr ==
				INADDR_ANY) {
			bzero(&dmask4, sizeof(dmask4));
		}
		p = encap_attach(sc->gif_psrc->sa_family, -1, sc->gif_psrc,
			(struct sockaddr *)&smask4, sc->gif_pdst,
			(struct sockaddr *)&dmask4,
			(struct protosw *)&in_gif_protosw, &sc->gif_if);
		if (p == NULL) {
			error = EINVAL;
			goto bad;
		}
		if (sc->encap_cookie != NULL)
			(void)encap_detach(sc->encap_cookie);
		sc->encap_cookie = p;
		sc->gif_oflags = ifp->if_flags;

		break;

	case SIOCSIFPHYADDR:
		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
			src = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_dstaddr);

			bzero(&smask4, sizeof(smask4));
			smask4.sin_addr.s_addr = ~0;
			dmask4 = smask4;
			if ((ifp->if_flags & IFF_LINK0) != 0 &&
			    ((struct sockaddr_in *)dst)->sin_addr.s_addr ==
					INADDR_ANY) {
				bzero(&dmask4, sizeof(dmask4));
			}
			size = sizeof(struct sockaddr_in);
			break;
		default:
			error = EAFNOSUPPORT;
			goto bad;
		}

		if (sc->encap_cookie)
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
			(struct sockaddr *)&smask4, dst,
			(struct sockaddr *)&dmask4,
			(struct protosw *)&in_gif_protosw, &sc->gif_if);
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
