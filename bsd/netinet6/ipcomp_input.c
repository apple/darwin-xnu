/*	$KAME: ipcomp_input.c,v 1.11 2000/02/22 14:04:23 itojun Exp $	*/

/*
 * Copyright (C) 1999 WIDE Project.
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
 * RFC2393 IP payload compression protocol (IPComp).
 */

#define _IP_VHL
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/zlib.h>
#include <kern/cpu_number.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_ecn.h>

#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet6/ipcomp.h>

#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <netkey/key_debug.h>

#include <net/net_osdep.h>

#define IPLEN_FLIPPED


#if INET
extern struct protosw * ip_protox[];
#if defined(__bsdi__) || defined(__NetBSD__)
extern u_char ip_protox[];
#endif

void
ipcomp4_input(struct mbuf *m, int off)
{
	struct ip *ip;
	struct ipcomp *ipcomp;
	struct ipcomp_algorithm *algo;
	u_int16_t cpi;	/* host order */
	u_int16_t nxt;
	size_t hlen;
	int error;
	size_t newlen, olen;
	struct secasvar *sav = NULL;


	if (off + sizeof(struct ipcomp) > MHLEN) {
		/*XXX the restriction should be relaxed*/
		ipseclog((LOG_DEBUG, "IPv4 IPComp input: assumption failed "
		    "(header too long)\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
	if (m->m_len < off + sizeof(struct ipcomp)) {
		m = m_pullup(m, off + sizeof(struct ipcomp));
		if (!m) {
			ipseclog((LOG_DEBUG, "IPv4 IPComp input: can't pullup;"
				"dropping the packet for simplicity\n"));
			ipsecstat.in_nomem++;
			goto fail;
		}
	} else if (m->m_len > off + sizeof(struct ipcomp)) {
		/* chop header part from the packet header chain */
		struct mbuf *n;
		MGETHDR(n, M_DONTWAIT, MT_HEADER);
		if (!n) {
			ipsecstat.in_nomem++;
			goto fail;
		}
		M_COPY_PKTHDR(n, m);
		MH_ALIGN(n, off + sizeof(struct ipcomp));
		n->m_len = off + sizeof(struct ipcomp);
		bcopy(mtod(m, caddr_t), mtod(n, caddr_t),
			off + sizeof(struct ipcomp));
		m_adj(m, off + sizeof(struct ipcomp));
		m->m_flags &= ~M_PKTHDR;
		n->m_next = m;
		m = n;
	}

	ip = mtod(m, struct ip *);
	ipcomp = (struct ipcomp *)(((caddr_t)ip) + off);
	nxt = ipcomp->comp_nxt;
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	cpi = ntohs(ipcomp->comp_cpi);

	if (cpi >= IPCOMP_CPI_NEGOTIATE_MIN) {
		sav = key_allocsa(AF_INET, (caddr_t)&ip->ip_src,
			(caddr_t)&ip->ip_dst, IPPROTO_IPCOMP, htonl(cpi));
		if (sav != NULL
		 && (sav->state == SADB_SASTATE_MATURE
		  || sav->state == SADB_SASTATE_DYING)) {
			cpi = sav->alg_enc;	/*XXX*/
			/* other parameters to look at? */
		}
	}
	if (cpi < IPCOMP_MAX && ipcomp_algorithms[cpi].decompress != NULL)
		algo = &ipcomp_algorithms[cpi];
	else
		algo = NULL;
	if (!algo) {
		ipseclog((LOG_WARNING, "IPv4 IPComp input: unknown cpi %u\n",
			cpi));
		ipsecstat.in_nosa++;
		goto fail;
	}

	/* chop ipcomp header */
	ipcomp = NULL;
	m->m_len -= sizeof(struct ipcomp);
	m->m_pkthdr.len -= sizeof(struct ipcomp);
#ifdef IPLEN_FLIPPED
	ip->ip_len -= sizeof(struct ipcomp);
#else
	ip->ip_len = htons(ntohs(ip->ip_len) - sizeof(struct ipcomp));
#endif

	olen = m->m_pkthdr.len;
	newlen = m->m_pkthdr.len - off;
	error = (*algo->decompress)(m, m->m_next, &newlen);
	if (error != 0) {
		if (error == EINVAL)
			ipsecstat.in_inval++;
		else if (error == ENOBUFS)
			ipsecstat.in_nomem++;
		m = NULL;
		goto fail;
	}
	ipsecstat.in_comphist[cpi]++;

	/*
	 * returning decompressed packet onto icmp is meaningless.
	 * mark it decrypted to prevent icmp from attaching original packet.
	 */
	m->m_flags |= M_DECRYPTED;

	m->m_pkthdr.len = off + newlen;
	ip = mtod(m, struct ip *);
    {
	size_t len;
#ifdef IPLEN_FLIPPED
	len = ip->ip_len;
#else
	len = ntohs(ip->ip_len);
#endif
	/*
	 * be careful about underflow.  also, do not assign exact value
	 * as ip_len is manipulated differently on *BSDs.
	 */
	len += m->m_pkthdr.len;
	len -= olen;
	if (len & ~0xffff) {
		/* packet too big after decompress */
		ipsecstat.in_inval++;
		goto fail;
	}
#ifdef IPLEN_FLIPPED
	ip->ip_len = len & 0xffff;
#else
	ip->ip_len = htons(len & 0xffff);
#endif
	ip->ip_p = nxt;
    }

	if (sav) {
		key_sa_recordxfer(sav, m);
		key_freesav(sav);
		sav = NULL;
	}

	if (nxt != IPPROTO_DONE)
		(*ip_protox[nxt]->pr_input)(m, off);
	else
		m_freem(m);
	m = NULL;

	ipsecstat.in_success++;
	return;

fail:
	if (sav)
		key_freesav(sav);
	if (m)
		m_freem(m);
	return;
}
#endif /* INET */

#if INET6
int
ipcomp6_input(mp, offp)
	struct mbuf **mp;
	int *offp;
{
	struct mbuf *m, *md;
	int off;
	struct ip6_hdr *ip6;
	struct mbuf *ipcompm;
	struct ipcomp *ipcomp;
	struct ipcomp_algorithm *algo;
	u_int16_t cpi;	/* host order */
	u_int16_t nxt;
	int error;
	size_t newlen;
	struct secasvar *sav = NULL;

	m = *mp;
	off = *offp;

	IP6_EXTHDR_CHECK(m, off, sizeof(struct ipcomp), IPPROTO_DONE);

    {
	int skip;
	struct mbuf *n;
	struct mbuf *p, *q;
	size_t l;

	skip = off;
	for (n = m; n && skip > 0; n = n->m_next) {
		if (n->m_len <= skip) {
			skip -= n->m_len;
			continue;
		}
		break;
	}
	if (!n) {
		ipseclog((LOG_DEBUG, "IPv6 IPComp input: wrong mbuf chain\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
	if (n->m_len < skip + sizeof(struct ipcomp)) {
		ipseclog((LOG_DEBUG, "IPv6 IPComp input: wrong mbuf chain\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	ipcompm = n;
	ipcomp = (struct ipcomp *)(mtod(n, caddr_t) + skip);
	if (n->m_len > skip + sizeof(struct ipcomp)) {
		/* split mbuf to ease the following steps*/
		l = n->m_len - (skip + sizeof(struct ipcomp));
		p = m_copym(n, skip + sizeof(struct ipcomp), l , M_DONTWAIT);
		if (!p) {
			ipsecstat.in_nomem++;
			goto fail;
		}
		for (q = p; q && q->m_next; q = q->m_next)
			;
		q->m_next = n->m_next;
		n->m_next = p;
		n->m_len -= l;
		md = p;
	} else
		md = n->m_next;
    }

	nxt = ipcomp->comp_nxt;
	cpi = ntohs(ipcomp->comp_cpi);

	if (cpi >= IPCOMP_CPI_NEGOTIATE_MIN) {
		sav = key_allocsa(AF_INET6, (caddr_t)&ip6->ip6_src,
			(caddr_t)&ip6->ip6_dst, IPPROTO_IPCOMP, htonl(cpi));
		if (sav != NULL
		 && (sav->state == SADB_SASTATE_MATURE
		  || sav->state == SADB_SASTATE_DYING)) {
			cpi = sav->alg_enc;	/*XXX*/
			/* other parameters to look at? */
		}
	}
	if (cpi < IPCOMP_MAX && ipcomp_algorithms[cpi].decompress != NULL)
		algo = &ipcomp_algorithms[cpi];
	else
		algo = NULL;
	if (!algo) {
		ipseclog((LOG_WARNING, "IPv6 IPComp input: unknown cpi %u; "
			"dropping the packet for simplicity\n", cpi));
		ipsec6stat.in_nosa++;
		goto fail;
	}

	newlen = m->m_pkthdr.len - off - sizeof(struct ipcomp);
	error = (*algo->decompress)(m, md, &newlen);
	if (error != 0) {
		if (error == EINVAL)
			ipsec6stat.in_inval++;
		else if (error == ENOBUFS)
			ipsec6stat.in_nomem++;
		m = NULL;
		goto fail;
	}
	ipsec6stat.in_comphist[cpi]++;
	m->m_pkthdr.len = off + sizeof(struct ipcomp) + newlen;

	/*
	 * returning decompressed packet onto icmp is meaningless.
	 * mark it decrypted to prevent icmp from attaching original packet.
	 */
	m->m_flags |= M_DECRYPTED;

    {
	char *prvnxtp;

	/* chop IPComp header */
	prvnxtp = ip6_get_prevhdr(m, off);
	*prvnxtp = nxt;
	ipcompm->m_len -= sizeof(struct ipcomp);
	ipcompm->m_pkthdr.len -= sizeof(struct ipcomp);

	/* adjust payload length */
	ip6 = mtod(m, struct ip6_hdr *);
	if (((m->m_pkthdr.len - sizeof(struct ip6_hdr)) & ~0xffff) != 0)
		ip6->ip6_plen = 0;	/*now a jumbogram*/
	else
		ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(struct ip6_hdr));
    }

	if (sav) {
		key_sa_recordxfer(sav, m);
		key_freesav(sav);
		sav = NULL;
	}
	*offp = off;
	*mp = m;
	ipsec6stat.in_success++;
	return nxt;

fail:
	if (m)
		m_freem(m);
	if (sav)
		key_freesav(sav);
	return IPPROTO_DONE;
}
#endif /* INET6 */
