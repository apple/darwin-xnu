/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
/*	$KAME: in_gif.c,v 1.54 2001/05/14 14:02:16 itojun Exp $	*/

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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <sys/malloc.h>
#include <libkern/OSAtomic.h>

#include <net/if.h>
#include <net/route.h>

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

#include <net/net_osdep.h>

int ip_gif_ttl = GIF_TTL;
SYSCTL_INT(_net_inet_ip, IPCTL_GIF_TTL, gifttl, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_gif_ttl,	0, "");

int
in_gif_output(
	struct ifnet	*ifp,
	int		family,
	struct mbuf	*m,
	__unused struct rtentry *rt)
{
	struct gif_softc *sc = ifnet_softc(ifp);
	struct sockaddr_in *dst = (struct sockaddr_in *)&sc->gif_ro.ro_dst;
	struct sockaddr_in *sin_src = (struct sockaddr_in *)sc->gif_psrc;
	struct sockaddr_in *sin_dst = (struct sockaddr_in *)sc->gif_pdst;
	struct ip iphdr;	/* capsule IP header, host byte ordered */
	int proto, error;
	u_int8_t tos;
	struct ip_out_args ipoa = { IFSCOPE_NONE, 0 };

	if (sin_src == NULL || sin_dst == NULL ||
	    sin_src->sin_family != AF_INET ||
	    sin_dst->sin_family != AF_INET) {
		m_freem(m);
		return EAFNOSUPPORT;
	}

	switch (family) {
#if INET
	case AF_INET:
	    {
		struct ip *ip;

		proto = IPPROTO_IPV4;
		if (mbuf_len(m) < sizeof(*ip)) {
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
		if (mbuf_len(m) < sizeof(*ip6)) {
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
	/* bidirectional configured tunnel mode */
	if (sin_dst->sin_addr.s_addr != INADDR_ANY)
		iphdr.ip_dst = sin_dst->sin_addr;
	else {
		m_freem(m);
		return ENETUNREACH;
	}
	iphdr.ip_p = proto;
	/* version will be set in ip_output() */
	iphdr.ip_ttl = ip_gif_ttl;
	iphdr.ip_len = m->m_pkthdr.len + sizeof(struct ip);
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &iphdr.ip_tos, &tos);
	else
		ip_ecn_ingress(ECN_NOCARE, &iphdr.ip_tos, &tos);

	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	if (m && mbuf_len(m) < sizeof(struct ip))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL) {
		printf("ENOBUFS in in_gif_output %d\n", __LINE__);
		return ENOBUFS;
	}
	bcopy(&iphdr, mtod(m, struct ip *), sizeof(struct ip));

	if (dst->sin_family != sin_dst->sin_family ||
	    dst->sin_addr.s_addr != sin_dst->sin_addr.s_addr ||
	    (sc->gif_ro.ro_rt != NULL &&
	    (sc->gif_ro.ro_rt->generation_id != route_generation ||
	    sc->gif_ro.ro_rt->rt_ifp == ifp))) {
		/* cache route doesn't match or recursive route */
		dst->sin_family = sin_dst->sin_family;
		dst->sin_len = sizeof(struct sockaddr_in);
		dst->sin_addr = sin_dst->sin_addr;
		if (sc->gif_ro.ro_rt) {
			rtfree(sc->gif_ro.ro_rt);
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

		/* if it constitutes infinite encapsulation, punt. */
		RT_LOCK(sc->gif_ro.ro_rt);
		if (sc->gif_ro.ro_rt->rt_ifp == ifp) {
			RT_UNLOCK(sc->gif_ro.ro_rt);
			m_freem(m);
			return ENETUNREACH;	/*XXX*/
		}
#if 0
		ifp->if_mtu = sc->gif_ro.ro_rt->rt_ifp->if_mtu
			- sizeof(struct ip);
#endif
		RT_UNLOCK(sc->gif_ro.ro_rt);
	}

	error = ip_output(m, NULL, &sc->gif_ro, IP_OUTARGS, NULL, &ipoa);
	return(error);
}

void
in_gif_input(m, off)
	struct mbuf *m;
	int off;
{
	struct ifnet *gifp = NULL;
	struct ip *ip;
	int af, proto;
	u_int8_t otos;

	ip = mtod(m, struct ip *);
	proto = ip->ip_p;


	gifp = ((struct gif_softc*)encap_getarg(m))->gif_if;

	if (gifp == NULL || (gifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		OSAddAtomic(1, &ipstat.ips_nogif);
		return;
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	switch (proto) {
#if INET
	case IPPROTO_IPV4:
	    {
		af = AF_INET;
		if (mbuf_len(m) < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m)
				return;
		}
		ip = mtod(m, struct ip *);
		if (gifp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &ip->ip_tos);
		else
			ip_ecn_egress(ECN_NOCARE, &otos, &ip->ip_tos);
		break;
	    }
#endif
#if INET6
	case IPPROTO_IPV6:
	    {
		struct ip6_hdr *ip6;
		u_int8_t itos;
		af = AF_INET6;
		if (mbuf_len(m) < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
		if (gifp->if_flags & IFF_LINK1)
			ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
		else
			ip_ecn_egress(ECN_NOCARE, &otos, &itos);
		ip6->ip6_flow &= ~htonl(0xff << 20);
		ip6->ip6_flow |= htonl((u_int32_t)itos << 20);
		break;
	    }
#endif /* INET6 */
	default:
		OSAddAtomic(1, &ipstat.ips_nogif);
		m_freem(m);
		return;
	}
#ifdef __APPLE__
	/* Should we free m if dlil_input returns an error? */
	if (m->m_pkthdr.rcvif)	/* replace the rcvif by gifp for dlil to route it correctly */
		m->m_pkthdr.rcvif = gifp;
	ifnet_input(gifp, m, NULL);
#else
	gif_input(m, af, gifp);
#endif
	return;
}

static __inline__ void*
_cast_non_const(const void * ptr) {
	union {
		const void*		cval;
		void*			val;
	} ret;
	
	ret.cval = ptr;
	return (ret.val);
}

/*
 * we know that we are in IFF_UP, outer address available, and outer family
 * matched the physical addr family.  see gif_encapcheck().
 */
int
gif_encapcheck4(
	const struct mbuf *m,
	__unused int off,
	__unused int proto,
	void *arg)
{
	struct ip ip;
	struct gif_softc *sc;
	struct sockaddr_in *src, *dst;
	int addrmatch;
	struct in_ifaddr *ia4;

	/* sanity check done in caller */
	sc = (struct gif_softc *)arg;
	src = (struct sockaddr_in *)sc->gif_psrc;
	dst = (struct sockaddr_in *)sc->gif_pdst;

	mbuf_copydata((struct mbuf *)(size_t)m, 0, sizeof(ip), &ip);

	/* check for address match */
	addrmatch = 0;
	if (src->sin_addr.s_addr == ip.ip_dst.s_addr)
		addrmatch |= 1;
	if (dst->sin_addr.s_addr == ip.ip_src.s_addr)
		addrmatch |= 2;
	if (addrmatch != 3)
		return 0;

	/* martian filters on outer source - NOT done in ip_input! */
	if (IN_MULTICAST(ntohl(ip.ip_src.s_addr)))
		return 0;
	switch ((ntohl(ip.ip_src.s_addr) & 0xff000000) >> 24) {
	case 0: case 127: case 255:
		return 0;
	}
	/* reject packets with broadcast on source */
	lck_rw_lock_shared(in_ifaddr_rwlock);
	for (ia4 = TAILQ_FIRST(&in_ifaddrhead); ia4;
	     ia4 = TAILQ_NEXT(ia4, ia_link))
	{
		if ((ifnet_flags(ia4->ia_ifa.ifa_ifp) & IFF_BROADCAST) == 0)
			continue;
		IFA_LOCK(&ia4->ia_ifa);
		if (ip.ip_src.s_addr == ia4->ia_broadaddr.sin_addr.s_addr) {
			IFA_UNLOCK(&ia4->ia_ifa);
			lck_rw_done(in_ifaddr_rwlock);
			return 0;
		}
		IFA_UNLOCK(&ia4->ia_ifa);
	}
	lck_rw_done(in_ifaddr_rwlock);

	/* ingress filters on outer source */
	if ((ifnet_flags(sc->gif_if) & IFF_LINK2) == 0 &&
	    (m->m_flags & M_PKTHDR) != 0 && m->m_pkthdr.rcvif) {
		struct sockaddr_in sin;
		struct rtentry *rt;

		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(struct sockaddr_in);
		sin.sin_addr = ip.ip_src;
		rt = rtalloc1_scoped((struct sockaddr *)&sin, 0, 0,
		    m->m_pkthdr.rcvif->if_index);
		if (rt != NULL)
			RT_LOCK(rt);
		if (rt == NULL || rt->rt_ifp != m->m_pkthdr.rcvif) {
			if (rt != NULL) {
				RT_UNLOCK(rt);
				rtfree(rt);
			}
			return 0;
		}
		RT_UNLOCK(rt);
		rtfree(rt);
	}

	return 32 * 2;
}
