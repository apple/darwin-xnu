/*	$FreeBSD: src/sys/netinet6/ipcomp_output.c,v 1.1.2.2 2001/07/03 11:01:54 ume Exp $	*/
/*	$KAME: ipcomp_output.c,v 1.23 2001/01/23 08:59:37 itojun Exp $	*/

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
#include <net/zlib.h>
#include <kern/cpu_number.h>
#include <kern/locks.h>

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
#if INET6
#include <netinet6/ipcomp6.h>
#endif

#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netkey/key.h>
#include <netkey/keydb.h>

#include <net/net_osdep.h>

extern lck_mtx_t  *sadb_mutex;

static int ipcomp_output(struct mbuf *, u_char *, struct mbuf *,
	struct ipsecrequest *, int);

/*
 * Modify the packet so that the payload is compressed.
 * The mbuf (m) must start with IPv4 or IPv6 header.
 * On failure, free the given mbuf and return non-zero.
 *
 * on invocation:
 *	m   nexthdrp md
 *	v   v        v
 *	IP ......... payload
 * during the encryption:
 *	m   nexthdrp mprev md
 *	v   v        v     v
 *	IP ............... ipcomp payload
 *	                   <-----><----->
 *	                   complen  plen
 *	<-> hlen
 *	<-----------------> compoff
 */
static int
ipcomp_output(m, nexthdrp, md, isr, af)
	struct mbuf *m;
	u_char *nexthdrp;
	struct mbuf *md;
	struct ipsecrequest *isr;
	int af;
{
	struct mbuf *n;
	struct mbuf *md0;
	struct mbuf *mcopy;
	struct mbuf *mprev;
	struct ipcomp *ipcomp;
	struct secasvar *sav = isr->sav;
	const struct ipcomp_algorithm *algo;
	u_int16_t cpi;		/* host order */
	size_t plen0, plen;	/*payload length to be compressed*/
	size_t compoff;
	int afnumber;
	int error = 0;
	struct ipsecstat *stat;

	switch (af) {
#if INET
	case AF_INET:
		afnumber = 4;
		stat = &ipsecstat;
		break;
#endif
#if INET6
	case AF_INET6:
		afnumber = 6;
		stat = &ipsec6stat;
		break;
#endif
	default:
		ipseclog((LOG_ERR, "ipcomp_output: unsupported af %d\n", af));
		return 0;	/* no change at all */
	}

	/* grab parameters */
	algo = ipcomp_algorithm_lookup(sav->alg_enc);
	if ((ntohl(sav->spi) & ~0xffff) != 0 || !algo) {
		stat->out_inval++;
		m_freem(m);
		return EINVAL;
	}
	if ((sav->flags & SADB_X_EXT_RAWCPI) == 0)
		cpi = sav->alg_enc;
	else
		cpi = ntohl(sav->spi) & 0xffff;

	/* compute original payload length */
	plen = 0;
	for (n = md; n; n = n->m_next)
		plen += n->m_len;

	/* if the payload is short enough, we don't need to compress */
	if (plen < algo->minplen)
		return 0;

	/*
	 * retain the original packet for two purposes:
	 * (1) we need to backout our changes when compression is not necessary.
	 * (2) byte lifetime computation should use the original packet.
	 *     see RFC2401 page 23.
	 * compromise two m_copym().  we will be going through every byte of
	 * the payload during compression process anyways.
	 */
	mcopy = m_copym(m, 0, M_COPYALL, M_NOWAIT);
	if (mcopy == NULL) {
		error = ENOBUFS;
		return 0;
	}
	md0 = m_copym(md, 0, M_COPYALL, M_NOWAIT);
	if (md0 == NULL) {
		m_freem(mcopy);
		error = ENOBUFS;
		return 0;
	}
	plen0 = plen;

	/* make the packet over-writable */
	for (mprev = m; mprev && mprev->m_next != md; mprev = mprev->m_next)
		;
	if (mprev == NULL || mprev->m_next != md) {
		ipseclog((LOG_DEBUG, "ipcomp%d_output: md is not in chain\n",
		    afnumber));
		stat->out_inval++;
		m_freem(m);
		m_freem(md0);
		m_freem(mcopy);
		return EINVAL;
	}
	mprev->m_next = NULL;
	if ((md = ipsec_copypkt(md)) == NULL) {
		m_freem(m);
		m_freem(md0);
		m_freem(mcopy);
		error = ENOBUFS;
		goto fail;
	}
	mprev->m_next = md;

	/* compress data part */
	lck_mtx_unlock(sadb_mutex);
	if ((*algo->compress)(m, md, &plen) || mprev->m_next == NULL) {
		lck_mtx_lock(sadb_mutex);
		ipseclog((LOG_ERR, "packet compression failure\n"));
		m = NULL;
		m_freem(md0);
		m_freem(mcopy);
		stat->out_inval++;
		error = EINVAL;
		goto fail;
	}
	lck_mtx_lock(sadb_mutex);
	stat->out_comphist[sav->alg_enc]++;
	md = mprev->m_next;

	/*
	 * if the packet became bigger, meaningless to use IPComp.
	 * we've only wasted our cpu time.
	 */
	if (plen0 < plen) {
		m_freem(md);
		m_freem(mcopy);
		mprev->m_next = md0;
		return 0;
	}

	/*
	 * no need to backout change beyond here.
	 */
	m_freem(md0);
	md0 = NULL;

	m->m_pkthdr.len -= plen0;
	m->m_pkthdr.len += plen;

    {
	/*
	 * insert IPComp header.
	 */
#if INET
	struct ip *ip = NULL;
#endif
#if INET6
	struct ip6_hdr *ip6 = NULL;
#endif
	size_t hlen = 0;	/*ip header len*/
	size_t complen = sizeof(struct ipcomp);

	switch (af) {
#if INET
	case AF_INET:
		ip = mtod(m, struct ip *);
#ifdef _IP_VHL
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
		hlen = ip->ip_hl << 2;
#endif
		break;
#endif
#if INET6
	case AF_INET6:
		ip6 = mtod(m, struct ip6_hdr *);
		hlen = sizeof(*ip6);
		break;
#endif
	}

	compoff = m->m_pkthdr.len - plen;

	/*
	 * grow the mbuf to accomodate ipcomp header.
	 * before: IP ... payload
	 * after:  IP ... ipcomp payload
	 */
	if (M_LEADINGSPACE(md) < complen) {
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			error = ENOBUFS;
			goto fail;
		}
		n->m_len = complen;
		mprev->m_next = n;
		n->m_next = md;
		m->m_pkthdr.len += complen;
		ipcomp = mtod(n, struct ipcomp *);
	} else {
		md->m_len += complen;
		md->m_data -= complen;
		m->m_pkthdr.len += complen;
		ipcomp = mtod(md, struct ipcomp *);
	}
	
	bzero(ipcomp, sizeof(*ipcomp));
	ipcomp->comp_nxt = *nexthdrp;
	*nexthdrp = IPPROTO_IPCOMP;
	ipcomp->comp_cpi = htons(cpi);
	switch (af) {
#if INET
	case AF_INET:
		if (compoff + complen + plen < IP_MAXPACKET)
			ip->ip_len = htons(compoff + complen + plen);
		else {
			ipseclog((LOG_ERR,
			    "IPv4 ESP output: size exceeds limit\n"));
			ipsecstat.out_inval++;
			m_freem(m);
			error = EMSGSIZE;
			goto fail;
		}
		break;
#endif
#if INET6
	case AF_INET6:
		/* total packet length will be computed in ip6_output() */
		break;
#endif
	}
    }

	if (!m) {
		ipseclog((LOG_DEBUG,
		    "NULL mbuf after compression in ipcomp%d_output",
		    afnumber));
		stat->out_inval++;
	}
		stat->out_success++;

	/* compute byte lifetime against original packet */
	key_sa_recordxfer(sav, mcopy);
	m_freem(mcopy);

	return 0;

fail:
#if 1
	return error;
#else
	panic("something bad in ipcomp_output");
#endif
}

#if INET
int
ipcomp4_output(m, isr)
	struct mbuf *m;
	struct ipsecrequest *isr;
{
	struct ip *ip;
	if (m->m_len < sizeof(struct ip)) {
		ipseclog((LOG_DEBUG, "ipcomp4_output: first mbuf too short\n"));
		ipsecstat.out_inval++;
		m_freem(m);
		return 0;
	}
	ip = mtod(m, struct ip *);
	/* XXX assumes that m->m_next points to payload */
	return ipcomp_output(m, &ip->ip_p, m->m_next, isr, AF_INET);
}
#endif /*INET*/

#ifdef INET6
int
ipcomp6_output(m, nexthdrp, md, isr)
	struct mbuf *m;
	u_char *nexthdrp;
	struct mbuf *md;
	struct ipsecrequest *isr;
{
	if (m->m_len < sizeof(struct ip6_hdr)) {
		ipseclog((LOG_DEBUG, "ipcomp6_output: first mbuf too short\n"));
		ipsec6stat.out_inval++;
		m_freem(m);
		return 0;
	}
	return ipcomp_output(m, nexthdrp, md, isr, AF_INET6);
}
#endif /*INET6*/
