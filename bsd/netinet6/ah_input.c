/*	$FreeBSD: src/sys/netinet6/ah_input.c,v 1.1.2.6 2002/04/28 05:40:26 suz Exp $	*/
/*	$KAME: ah_input.c,v 1.67 2002/01/07 11:39:56 kjc Exp $	*/

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
 * RFC1826/2402 authentication header.
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
#include <kern/cpu_number.h>
#include <kern/locks.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_ecn.h>
#include <netinet/in_pcb.h>
#if INET6
#include <netinet6/ip6_ecn.h>
#endif

#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6protosw.h>
#endif

#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#include <netkey/key.h>
#include <netkey/keydb.h>
#if IPSEC_DEBUG
#include <netkey/key_debug.h>
#else
#define	KEYDEBUG(lev,arg)
#endif


#include <net/net_osdep.h>

#define IPLEN_FLIPPED

extern lck_mtx_t *sadb_mutex;
#if INET
extern struct protosw inetsw[];

void
ah4_input(struct mbuf *m, int off)
{
	struct ip *ip;
	struct ah *ah;
	u_int32_t spi;
	const struct ah_algorithm *algo;
	size_t siz;
	size_t siz1;
	u_char *cksum;
	struct secasvar *sav = NULL;
	u_int16_t nxt;
	size_t hlen;
	int s;
	size_t stripsiz = 0;

	lck_mtx_lock(sadb_mutex);

#ifndef PULLDOWN_TEST
	if (m->m_len < off + sizeof(struct newah)) {
		m = m_pullup(m, off + sizeof(struct newah));
		if (!m) {
			ipseclog((LOG_DEBUG, "IPv4 AH input: can't pullup;"
				"dropping the packet for simplicity\n"));
			ipsecstat.in_inval++;
			goto fail;
		}
	}

	ip = mtod(m, struct ip *);
	ah = (struct ah *)(((caddr_t)ip) + off);
#else
	ip = mtod(m, struct ip *);
	IP6_EXTHDR_GET(ah, struct ah *, m, off, sizeof(struct newah));
	if (ah == NULL) {
		ipseclog((LOG_DEBUG, "IPv4 AH input: can't pullup;"
			"dropping the packet for simplicity\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
#endif
	nxt = ah->ah_nxt;
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	/* find the sassoc. */
	spi = ah->ah_spi;

	if ((sav = key_allocsa(AF_INET,
	                      (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst,
	                      IPPROTO_AH, spi)) == 0) {
		ipseclog((LOG_WARNING,
		    "IPv4 AH input: no key association found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		ipsecstat.in_nosa++;
		goto fail;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ah4_input called to allocate SA:%p\n", sav));
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		ipseclog((LOG_DEBUG,
		    "IPv4 AH input: non-mature/dying SA found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		ipsecstat.in_badspi++;
		goto fail;
	}

	algo = ah_algorithm_lookup(sav->alg_auth);
	if (!algo) {
		ipseclog((LOG_DEBUG, "IPv4 AH input: "
		    "unsupported authentication algorithm for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		ipsecstat.in_badspi++;
		goto fail;
	}

	siz = (*algo->sumsiz)(sav);
	siz1 = ((siz + 3) & ~(4 - 1));

	/*
	 * sanity checks for header, 1.
	 */
    {
	int sizoff;

	sizoff = (sav->flags & SADB_X_EXT_OLD) ? 0 : 4;

	/*
	 * Here, we do not do "siz1 == siz".  This is because the way
	 * RFC240[34] section 2 is written.  They do not require truncation
	 * to 96 bits.
	 * For example, Microsoft IPsec stack attaches 160 bits of
	 * authentication data for both hmac-md5 and hmac-sha1.  For hmac-sha1,
	 * 32 bits of padding is attached.
	 *
	 * There are two downsides to this specification.
	 * They have no real harm, however, they leave us fuzzy feeling.
	 * - if we attach more than 96 bits of authentication data onto AH,
	 *   we will never notice about possible modification by rogue
	 *   intermediate nodes.
	 *   Since extra bits in AH checksum is never used, this constitutes
	 *   no real issue, however, it is wacky.
	 * - even if the peer attaches big authentication data, we will never
	 *   notice the difference, since longer authentication data will just
	 *   work.
	 *
	 * We may need some clarification in the spec.
	 */
	if (siz1 < siz) {
		ipseclog((LOG_NOTICE, "sum length too short in IPv4 AH input "
		    "(%lu, should be at least %lu): %s\n",
		    (u_long)siz1, (u_long)siz,
		    ipsec4_logpacketstr(ip, spi)));
		ipsecstat.in_inval++;
		goto fail;
	}
	if ((ah->ah_len << 2) - sizoff != siz1) {
		ipseclog((LOG_NOTICE, "sum length mismatch in IPv4 AH input "
		    "(%d should be %lu): %s\n",
		    (ah->ah_len << 2) - sizoff, (u_long)siz1,
		    ipsec4_logpacketstr(ip, spi)));
		ipsecstat.in_inval++;
		goto fail;
	}

#ifndef PULLDOWN_TEST
	if (m->m_len < off + sizeof(struct ah) + sizoff + siz1) {
		m = m_pullup(m, off + sizeof(struct ah) + sizoff + siz1);
		if (!m) {
			ipseclog((LOG_DEBUG, "IPv4 AH input: can't pullup\n"));
			ipsecstat.in_inval++;
			goto fail;
		}

		ip = mtod(m, struct ip *);
		ah = (struct ah *)(((caddr_t)ip) + off);
	}
#else
	IP6_EXTHDR_GET(ah, struct ah *, m, off,
		sizeof(struct ah) + sizoff + siz1);
	if (ah == NULL) {
		ipseclog((LOG_DEBUG, "IPv4 AH input: can't pullup\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
#endif
    }

	/*
	 * check for sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_chkreplay(ntohl(((struct newah *)ah)->ah_seq), sav))
			; /*okey*/
		else {
			ipsecstat.in_ahreplay++;
			ipseclog((LOG_WARNING,
			    "replay packet in IPv4 AH input: %s %s\n",
			    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
			goto fail;
		}
	}

	/*
	 * alright, it seems sane.  now we are going to check the
	 * cryptographic checksum.
	 */
	cksum = _MALLOC(siz1, M_TEMP, M_NOWAIT);
	if (!cksum) {
		ipseclog((LOG_DEBUG, "IPv4 AH input: "
		    "couldn't alloc temporary region for cksum\n"));
		ipsecstat.in_inval++;
		goto fail;
	}
	
	/*
	 * some of IP header fields are flipped to the host endian.
	 * convert them back to network endian.  VERY stupid.
	 */
	ip->ip_len = htons(ip->ip_len + hlen);
	ip->ip_off = htons(ip->ip_off);
	if (ah4_calccksum(m, (caddr_t)cksum, siz1, algo, sav)) {
		FREE(cksum, M_TEMP);
		ipsecstat.in_inval++;
		goto fail;
	}
	ipsecstat.in_ahhist[sav->alg_auth]++;
	/*
	 * flip them back.
	 */
	ip->ip_len = ntohs(ip->ip_len) - hlen;
	ip->ip_off = ntohs(ip->ip_off);

    {
	caddr_t sumpos = NULL;

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1826 */
		sumpos = (caddr_t)(ah + 1);
	} else {
		/* RFC 2402 */
		sumpos = (caddr_t)(((struct newah *)ah) + 1);
	}

	if (bcmp(sumpos, cksum, siz) != 0) {
		ipseclog((LOG_WARNING,
		    "checksum mismatch in IPv4 AH input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		FREE(cksum, M_TEMP);
		ipsecstat.in_ahauthfail++;
		goto fail;
	}
    }

	FREE(cksum, M_TEMP);

	m->m_flags |= M_AUTHIPHDR;
	m->m_flags |= M_AUTHIPDGM;

#if 0
	/*
	 * looks okey, but we need more sanity check.
	 * XXX should elaborate.
	 */
	if (ah->ah_nxt == IPPROTO_IPIP || ah->ah_nxt == IPPROTO_IP) {
		struct ip *nip;
		size_t sizoff;

		sizoff = (sav->flags & SADB_X_EXT_OLD) ? 0 : 4;

		if (m->m_len < off + sizeof(struct ah) + sizoff + siz1 + hlen) {
			m = m_pullup(m, off + sizeof(struct ah)
					+ sizoff + siz1 + hlen);
			if (!m) {
				ipseclog((LOG_DEBUG,
				    "IPv4 AH input: can't pullup\n"));
				ipsecstat.in_inval++;
				goto fail;
			}
		}

		nip = (struct ip *)((u_char *)(ah + 1) + sizoff + siz1);
		if (nip->ip_src.s_addr != ip->ip_src.s_addr
		 || nip->ip_dst.s_addr != ip->ip_dst.s_addr) {
			m->m_flags &= ~M_AUTHIPHDR;
			m->m_flags &= ~M_AUTHIPDGM;
		}
	}
#if INET6
	else if (ah->ah_nxt == IPPROTO_IPV6) {
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
	}
#endif /*INET6*/
#endif /*0*/

	if (m->m_flags & M_AUTHIPHDR
	 && m->m_flags & M_AUTHIPDGM) {
#if 0
		ipseclog((LOG_DEBUG,
		    "IPv4 AH input: authentication succeess\n"));
#endif
		ipsecstat.in_ahauthsucc++;
	} else {
		ipseclog((LOG_WARNING,
		    "authentication failed in IPv4 AH input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		ipsecstat.in_ahauthfail++;
		goto fail;
	}

	/*
	 * update sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_updatereplay(ntohl(((struct newah *)ah)->ah_seq), sav)) {
			ipsecstat.in_ahreplay++;
			goto fail;
		}
	}

	/* was it transmitted over the IPsec tunnel SA? */
	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1826 */
		stripsiz = sizeof(struct ah) + siz1;
	} else {
		/* RFC 2402 */
		stripsiz = sizeof(struct newah) + siz1;
	}
	if (ipsec4_tunnel_validate(m, off + stripsiz, nxt, sav)) {
		/*
		 * strip off all the headers that precedes AH.
		 *	IP xx AH IP' payload -> IP' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
		u_int8_t tos;

		tos = ip->ip_tos;
		m_adj(m, off + stripsiz);
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m) {
				ipsecstat.in_inval++;
				goto fail;
			}
		}
		ip = mtod(m, struct ip *);
		/* ECN consideration. */
		ip_ecn_egress(ip4_ipsec_ecn, &tos, &ip->ip_tos);
		if (!key_checktunnelsanity(sav, AF_INET,
			    (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst)) {
			ipseclog((LOG_NOTICE, "ipsec tunnel address mismatch "
			    "in IPv4 AH input: %s %s\n",
			    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
			ipsecstat.in_inval++;
			goto fail;
		}

#if 1
		/*
		 * Should the inner packet be considered authentic?
		 * My current answer is: NO.
		 *
		 * host1 -- gw1 === gw2 -- host2
		 *	In this case, gw2 can trust the	authenticity of the
		 *	outer packet, but NOT inner.  Packet may be altered
		 *	between host1 and gw1.
		 *
		 * host1 -- gw1 === host2
		 *	This case falls into the same scenario as above.
		 *
		 * host1 === host2
		 *	This case is the only case when we may be able to leave
		 *	M_AUTHIPHDR and M_AUTHIPDGM set.
		 *	However, if host1 is wrongly configured, and allows
		 *	attacker to inject some packet with src=host1 and
		 *	dst=host2, you are in risk.
		 */
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
#endif

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_AH, spi) != 0 ||
		    ipsec_addhist(m, IPPROTO_IPV4, 0) != 0) {
			ipsecstat.in_nomem++;
			goto fail;
		}
		lck_mtx_unlock(sadb_mutex);
		proto_input(PF_INET, m);
		lck_mtx_lock(sadb_mutex);
		nxt = IPPROTO_DONE;
	} else {
		/*
		 * strip off AH.
		 */

		ip = mtod(m, struct ip *);
#ifndef PULLDOWN_TEST
		/*
		 * We do deep-copy since KAME requires that
		 * the packet is placed in a single external mbuf.
		 */
		ovbcopy((caddr_t)ip, (caddr_t)(((u_char *)ip) + stripsiz), off);
		m->m_data += stripsiz;
		m->m_len -= stripsiz;
		m->m_pkthdr.len -= stripsiz;
#else
		/*
		 * even in m_pulldown case, we need to strip off AH so that
		 * we can compute checksum for multiple AH correctly.
		 */
		if (m->m_len >= stripsiz + off) {
			ovbcopy((caddr_t)ip, ((caddr_t)ip) + stripsiz, off);
			m->m_data += stripsiz;
			m->m_len -= stripsiz;
			m->m_pkthdr.len -= stripsiz;
		} else {
			/*
			 * this comes with no copy if the boundary is on
			 * cluster
			 */
			struct mbuf *n;

			n = m_split(m, off, M_DONTWAIT);
			if (n == NULL) {
				/* m is retained by m_split */
				goto fail;
			}
			m_adj(n, stripsiz);
			/* m_cat does not update m_pkthdr.len */
			m->m_pkthdr.len += n->m_pkthdr.len;
			m_cat(m, n);
		}
#endif

		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (m == NULL) {
				ipsecstat.in_inval++;
				goto fail;
			}
		}
		ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
		ip->ip_len = ip->ip_len - stripsiz;
#else
		ip->ip_len = htons(ntohs(ip->ip_len) - stripsiz);
#endif
		ip->ip_p = nxt;
		/* forget about IP hdr checksum, the check has already been passed */

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_AH, spi) != 0) {
			ipsecstat.in_nomem++;
			goto fail;
		}

		if (nxt != IPPROTO_DONE) {
			if ((ip_protox[nxt]->pr_flags & PR_LASTHDR) != 0 &&
			    ipsec4_in_reject(m, NULL)) {
				ipsecstat.in_polvio++;
				goto fail;
			}
			lck_mtx_unlock(sadb_mutex);
			ip_proto_dispatch_in(m, off, nxt, 0);
			lck_mtx_lock(sadb_mutex);
		} else
			m_freem(m);
		m = NULL;
	}

	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ah4_input call free SA:%p\n", sav));
		key_freesav(sav);
	}
	ipsecstat.in_success++;
	lck_mtx_unlock(sadb_mutex);
	return;

fail:
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ah4_input call free SA:%p\n", sav));
		key_freesav(sav);
	}
	lck_mtx_unlock(sadb_mutex);
	if (m)
		m_freem(m);
	return;
}
#endif /* INET */

#if INET6
int
ah6_input(mp, offp)
	struct mbuf **mp;
	int *offp;
{
	struct mbuf *m = *mp;
	int off = *offp;
	struct ip6_hdr *ip6;
	struct ah *ah;
	u_int32_t spi;
	const struct ah_algorithm *algo;
	size_t siz;
	size_t siz1;
	u_char *cksum;
	struct secasvar *sav = NULL;
	u_int16_t nxt;
	int s;
	size_t stripsiz = 0;

	lck_mtx_lock(sadb_mutex);

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(struct ah), {lck_mtx_unlock(sadb_mutex);return IPPROTO_DONE;});
	ah = (struct ah *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(ah, struct ah *, m, off, sizeof(struct newah));
	if (ah == NULL) {
		ipseclog((LOG_DEBUG, "IPv6 AH input: can't pullup\n"));
		ipsec6stat.in_inval++;
		lck_mtx_unlock(sadb_mutex);
		return IPPROTO_DONE;
	}
#endif
	ip6 = mtod(m, struct ip6_hdr *);
	nxt = ah->ah_nxt;

	/* find the sassoc.  */
	spi = ah->ah_spi;

	if (ntohs(ip6->ip6_plen) == 0) {
		ipseclog((LOG_ERR, "IPv6 AH input: "
		    "AH with IPv6 jumbogram is not supported.\n"));
		ipsec6stat.in_inval++;
		goto fail;
	}

	if ((sav = key_allocsa(AF_INET6,
	                      (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst,
	                      IPPROTO_AH, spi)) == 0) {
		ipseclog((LOG_WARNING,
		    "IPv6 AH input: no key association found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		ipsec6stat.in_nosa++;
		goto fail;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP ah6_input called to allocate SA:%p\n", sav));
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		ipseclog((LOG_DEBUG,
		    "IPv6 AH input: non-mature/dying SA found for spi %u; ",
		    (u_int32_t)ntohl(spi)));
		ipsec6stat.in_badspi++;
		goto fail;
	}

	algo = ah_algorithm_lookup(sav->alg_auth);
	if (!algo) {
		ipseclog((LOG_DEBUG, "IPv6 AH input: "
		    "unsupported authentication algorithm for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		ipsec6stat.in_badspi++;
		goto fail;
	}

	siz = (*algo->sumsiz)(sav);
	siz1 = ((siz + 3) & ~(4 - 1));

	/*
	 * sanity checks for header, 1.
	 */
    {
	int sizoff;

	sizoff = (sav->flags & SADB_X_EXT_OLD) ? 0 : 4;

	/*
	 * Here, we do not do "siz1 == siz".  See ah4_input() for complete
	 * description.
	 */
	if (siz1 < siz) {
		ipseclog((LOG_NOTICE, "sum length too short in IPv6 AH input "
		    "(%lu, should be at least %lu): %s\n",
		    (u_long)siz1, (u_long)siz,
		    ipsec6_logpacketstr(ip6, spi)));
		ipsec6stat.in_inval++;
		goto fail;
	}
	if ((ah->ah_len << 2) - sizoff != siz1) {
		ipseclog((LOG_NOTICE, "sum length mismatch in IPv6 AH input "
		    "(%d should be %lu): %s\n",
		    (ah->ah_len << 2) - sizoff, (u_long)siz1,
		    ipsec6_logpacketstr(ip6, spi)));
		ipsec6stat.in_inval++;
		goto fail;
	}
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(struct ah) + sizoff + siz1, 
		{lck_mtx_unlock(sadb_mutex);return IPPROTO_DONE;});
#else
	IP6_EXTHDR_GET(ah, struct ah *, m, off,
		sizeof(struct ah) + sizoff + siz1);
	if (ah == NULL) {
		ipseclog((LOG_NOTICE, "couldn't pullup gather IPv6 AH checksum part"));
		ipsec6stat.in_inval++;
		m = NULL;
		goto fail;
	}
#endif
    }

	/*
	 * check for sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_chkreplay(ntohl(((struct newah *)ah)->ah_seq), sav))
			; /*okey*/
		else {
			ipsec6stat.in_ahreplay++;
			ipseclog((LOG_WARNING,
			    "replay packet in IPv6 AH input: %s %s\n",
			    ipsec6_logpacketstr(ip6, spi),
			    ipsec_logsastr(sav)));
			goto fail;
		}
	}

	/*
	 * alright, it seems sane.  now we are going to check the
	 * cryptographic checksum.
	 */
	cksum = _MALLOC(siz1, M_TEMP, M_NOWAIT);
	if (!cksum) {
		ipseclog((LOG_DEBUG, "IPv6 AH input: "
		    "couldn't alloc temporary region for cksum\n"));
		ipsec6stat.in_inval++;
		goto fail;
	}
	
	if (ah6_calccksum(m, (caddr_t)cksum, siz1, algo, sav)) {
		FREE(cksum, M_TEMP);
		ipsec6stat.in_inval++;
		goto fail;
	}
	ipsec6stat.in_ahhist[sav->alg_auth]++;

    {
	caddr_t sumpos = NULL;

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1826 */
		sumpos = (caddr_t)(ah + 1);
	} else {
		/* RFC 2402 */
		sumpos = (caddr_t)(((struct newah *)ah) + 1);
	}

	if (bcmp(sumpos, cksum, siz) != 0) {
		ipseclog((LOG_WARNING,
		    "checksum mismatch in IPv6 AH input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		FREE(cksum, M_TEMP);
		ipsec6stat.in_ahauthfail++;
		goto fail;
	}
    }

	FREE(cksum, M_TEMP);

	m->m_flags |= M_AUTHIPHDR;
	m->m_flags |= M_AUTHIPDGM;

#if 0
	/*
	 * looks okey, but we need more sanity check.
	 * XXX should elaborate.
	 */
	if (ah->ah_nxt == IPPROTO_IPV6) {
		struct ip6_hdr *nip6;
		size_t sizoff;

		sizoff = (sav->flags & SADB_X_EXT_OLD) ? 0 : 4;

		IP6_EXTHDR_CHECK(m, off, sizeof(struct ah) + sizoff + siz1
				+ sizeof(struct ip6_hdr), 
				{lck_mtx_unlock(sadb_mutex);return IPPROTO_DONE;});

		nip6 = (struct ip6_hdr *)((u_char *)(ah + 1) + sizoff + siz1);
		if (!IN6_ARE_ADDR_EQUAL(&nip6->ip6_src, &ip6->ip6_src)
		 || !IN6_ARE_ADDR_EQUAL(&nip6->ip6_dst, &ip6->ip6_dst)) {
			m->m_flags &= ~M_AUTHIPHDR;
			m->m_flags &= ~M_AUTHIPDGM;
		}
	} else if (ah->ah_nxt == IPPROTO_IPIP) {
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
	} else if (ah->ah_nxt == IPPROTO_IP) {
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
	}
#endif

	if (m->m_flags & M_AUTHIPHDR
	 && m->m_flags & M_AUTHIPDGM) {
#if 0
		ipseclog((LOG_DEBUG,
		    "IPv6 AH input: authentication succeess\n"));
#endif
		ipsec6stat.in_ahauthsucc++;
	} else {
		ipseclog((LOG_WARNING,
		    "authentication failed in IPv6 AH input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		ipsec6stat.in_ahauthfail++;
		goto fail;
	}

	/*
	 * update sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_updatereplay(ntohl(((struct newah *)ah)->ah_seq), sav)) {
			ipsec6stat.in_ahreplay++;
			goto fail;
		}
	}

	/* was it transmitted over the IPsec tunnel SA? */
	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1826 */
		stripsiz = sizeof(struct ah) + siz1;
	} else {
		/* RFC 2402 */
		stripsiz = sizeof(struct newah) + siz1;
	}
	if (ipsec6_tunnel_validate(m, off + stripsiz, nxt, sav)) {
		/*
		 * strip off all the headers that precedes AH.
		 *	IP6 xx AH IP6' payload -> IP6' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
		u_int32_t flowinfo;	/*net endian*/

		flowinfo = ip6->ip6_flow;
		m_adj(m, off + stripsiz);
		if (m->m_len < sizeof(*ip6)) {
			/*
			 * m_pullup is prohibited in KAME IPv6 input processing
			 * but there's no other way!
			 */
			m = m_pullup(m, sizeof(*ip6));
			if (!m) {
				ipsec6stat.in_inval++;
				goto fail;
			}
		}
		ip6 = mtod(m, struct ip6_hdr *);
		/* ECN consideration. */
		ip6_ecn_egress(ip6_ipsec_ecn, &flowinfo, &ip6->ip6_flow);
		if (!key_checktunnelsanity(sav, AF_INET6,
			    (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst)) {
			ipseclog((LOG_NOTICE, "ipsec tunnel address mismatch "
			    "in IPv6 AH input: %s %s\n",
			    ipsec6_logpacketstr(ip6, spi),
			    ipsec_logsastr(sav)));
			ipsec6stat.in_inval++;
			goto fail;
		}

#if 1
		/*
		 * should the inner packet be considered authentic?
		 * see comment in ah4_input().
		 */
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
#endif

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_AH, spi) != 0 ||
		    ipsec_addhist(m, IPPROTO_IPV6, 0) != 0) {
			ipsec6stat.in_nomem++;
			goto fail;
		}
		lck_mtx_unlock(sadb_mutex);
		proto_input(PF_INET6, m);
		lck_mtx_lock(sadb_mutex);
		nxt = IPPROTO_DONE;
	} else {
		/*
		 * strip off AH.
		 */
		char *prvnxtp;

		/*
		 * Copy the value of the next header field of AH to the
		 * next header field of the previous header.
		 * This is necessary because AH will be stripped off below.
		 */
		prvnxtp = ip6_get_prevhdr(m, off); /* XXX */
		*prvnxtp = nxt;

		ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
		/*
		 * We do deep-copy since KAME requires that
		 * the packet is placed in a single mbuf.
		 */
		ovbcopy((caddr_t)ip6, ((caddr_t)ip6) + stripsiz, off);
		m->m_data += stripsiz;
		m->m_len -= stripsiz;
		m->m_pkthdr.len -= stripsiz;
#else
		/*
		 * even in m_pulldown case, we need to strip off AH so that
		 * we can compute checksum for multiple AH correctly.
		 */
		if (m->m_len >= stripsiz + off) {
			ovbcopy((caddr_t)ip6, ((caddr_t)ip6) + stripsiz, off);
			m->m_data += stripsiz;
			m->m_len -= stripsiz;
			m->m_pkthdr.len -= stripsiz;
		} else {
			/*
			 * this comes with no copy if the boundary is on
			 * cluster
			 */
			struct mbuf *n;

			n = m_split(m, off, M_DONTWAIT);
			if (n == NULL) {
				/* m is retained by m_split */
				goto fail;
			}
			m_adj(n, stripsiz);
			/* m_cat does not update m_pkthdr.len */
			m->m_pkthdr.len += n->m_pkthdr.len;
			m_cat(m, n);
		}
#endif
		ip6 = mtod(m, struct ip6_hdr *);
		/* XXX jumbogram */
		ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - stripsiz);

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_AH, spi) != 0) {
			ipsec6stat.in_nomem++;
			goto fail;
		}
	}

	*offp = off;
	*mp = m;

	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ah6_input call free SA:%p\n", sav));
		key_freesav(sav);
	}
	ipsec6stat.in_success++;
	lck_mtx_unlock(sadb_mutex);
	return nxt;

fail:
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ah6_input call free SA:%p\n", sav));
		key_freesav(sav);
	}
	lck_mtx_unlock(sadb_mutex);
	if (m)
		m_freem(m);
	return IPPROTO_DONE;
}

void
ah6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	const struct newah *ahp;
	struct newah ah;
	struct secasvar *sav;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	struct ip6ctlparam *ip6cp = NULL;
	int off;
	struct sockaddr_in6 *sa6_src, *sa6_dst;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;
	if ((unsigned)cmd >= PRC_NCMDS)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
	} else {
		m = NULL;
		ip6 = NULL;
	}

	if (ip6) {
		/*
		 * XXX: We assume that when ip6 is non NULL,
		 * M and OFF are valid.
		 */

		/* check if we can safely examine src and dst ports */
		if (m->m_pkthdr.len < off + sizeof(ah))
			return;

		if (m->m_len < off + sizeof(ah)) {
			/*
			 * this should be rare case,
			 * so we compromise on this copy...
			 */
			m_copydata(m, off, sizeof(ah), (caddr_t)&ah);
			ahp = &ah;
		} else
			ahp = (struct newah *)(mtod(m, caddr_t) + off);

		if (cmd == PRC_MSGSIZE) {
			int valid = 0;

			/*
			 * Check to see if we have a valid SA corresponding to
			 * the address in the ICMP message payload.
			 */
			sa6_src = ip6cp->ip6c_src;
			sa6_dst = (struct sockaddr_in6 *)sa;
			lck_mtx_lock(sadb_mutex);
			sav = key_allocsa(AF_INET6,
					  (caddr_t)&sa6_src->sin6_addr,
					  (caddr_t)&sa6_dst->sin6_addr,
					  IPPROTO_AH, ahp->ah_spi);
			if (sav) {
				if (sav->state == SADB_SASTATE_MATURE ||
				    sav->state == SADB_SASTATE_DYING)
					valid++;
				key_freesav(sav);
			}
			lck_mtx_unlock(sadb_mutex);

			/* XXX Further validation? */

			/*
			 * Depending on the value of "valid" and routing table
			 * size (mtudisc_{hi,lo}wat), we will:
			 * - recalcurate the new MTU and create the
			 *   corresponding routing entry, or
			 * - ignore the MTU change notification.
			 */
			icmp6_mtudisc_update((struct ip6ctlparam *)d, valid);
		}

		/* we normally notify single pcb here */
	} else {
		/* we normally notify any pcb here */
	}
}
#endif /* INET6 */
