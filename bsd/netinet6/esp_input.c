/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_input.c,v 1.1.2.3 2001/07/03 11:01:50 ume Exp $	*/
/*	$KAME: esp_input.c,v 1.55 2001/03/23 08:08:47 itojun Exp $	*/

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
 * RFC1827/2406 Encapsulated Security Payload.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_ipsec.h>
#include <net/route.h>
#include <kern/cpu_number.h>
#include <kern/locks.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/ip_ecn.h>
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#if INET6
#include <netinet6/ip6_ecn.h>
#endif

#if INET6
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
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
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <netkey/key_debug.h>

#include <net/kpi_protocol.h>
#include <netinet/kpi_ipfilter_var.h>

#include <net/net_osdep.h>
#include <mach/sdt.h>
#include <corecrypto/cc.h>

#include <sys/kdebug.h>
#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIPSEC, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETIPSEC, 3)
#define DBG_FNC_ESPIN		NETDBG_CODE(DBG_NETIPSEC, (6 << 8))
#define DBG_FNC_DECRYPT		NETDBG_CODE(DBG_NETIPSEC, (7 << 8))
#define IPLEN_FLIPPED

extern lck_mtx_t  *sadb_mutex;

#if INET
#define ESPMAXLEN \
	(sizeof(struct esp) < sizeof(struct newesp) \
		? sizeof(struct newesp) : sizeof(struct esp))

static struct ip *
esp4_input_strip_udp_encap (struct mbuf *m, int iphlen)
{
	// strip the udp header that's encapsulating ESP
	struct ip *ip;
	size_t     stripsiz = sizeof(struct udphdr);

	ip = mtod(m, __typeof__(ip));
	ovbcopy((caddr_t)ip, (caddr_t)(((u_char *)ip) + stripsiz), iphlen);
	m->m_data += stripsiz;
	m->m_len -= stripsiz;
	m->m_pkthdr.len -= stripsiz;
	ip = mtod(m, __typeof__(ip));
	ip->ip_len = ip->ip_len - stripsiz;
	ip->ip_p = IPPROTO_ESP;
	return ip;
}

static struct ip6_hdr *
esp6_input_strip_udp_encap (struct mbuf *m, int ip6hlen)
{
	// strip the udp header that's encapsulating ESP
	struct ip6_hdr *ip6;
	size_t     stripsiz = sizeof(struct udphdr);

	ip6 = mtod(m, __typeof__(ip6));
	ovbcopy((caddr_t)ip6, (caddr_t)(((u_char *)ip6) + stripsiz), ip6hlen);
	m->m_data += stripsiz;
	m->m_len -= stripsiz;
	m->m_pkthdr.len -= stripsiz;
	ip6 = mtod(m, __typeof__(ip6));
	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - stripsiz);
	ip6->ip6_nxt = IPPROTO_ESP;
	return ip6;
}

void
esp4_input(struct mbuf *m, int off)
{
	(void)esp4_input_extended(m, off, NULL);
}

struct mbuf *
esp4_input_extended(struct mbuf *m, int off, ifnet_t interface)
{
	struct ip *ip;
#if INET6
	struct ip6_hdr *ip6;
#endif /* INET6 */
	struct esp *esp;
	struct esptail esptail;
	u_int32_t spi;
	u_int32_t seq;
	struct secasvar *sav = NULL;
	size_t taillen;
	u_int16_t nxt;
	const struct esp_algorithm *algo;
	int ivlen;
	size_t hlen;
	size_t esplen;
	sa_family_t	ifamily;
	struct mbuf *out_m = NULL;

	KERNEL_DEBUG(DBG_FNC_ESPIN | DBG_FUNC_START, 0,0,0,0,0);
	/* sanity check for alignment. */
	if (off % 4 != 0 || m->m_pkthdr.len % 4 != 0) {
		ipseclog((LOG_ERR, "IPv4 ESP input: packet alignment problem "
			"(off=%d, pktlen=%d)\n", off, m->m_pkthdr.len));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	if (m->m_len < off + ESPMAXLEN) {
		m = m_pullup(m, off + ESPMAXLEN);
		if (!m) {
			ipseclog((LOG_DEBUG,
			    "IPv4 ESP input: can't pullup in esp4_input\n"));
			IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
			goto bad;
		}
	}

	m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip = mtod(m, struct ip *);
	// expect udp-encap and esp packets only
	if (ip->ip_p != IPPROTO_ESP &&
	    !(ip->ip_p == IPPROTO_UDP && off >= sizeof(struct udphdr))) {
		ipseclog((LOG_DEBUG,
			  "IPv4 ESP input: invalid protocol type\n"));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}
	esp = (struct esp *)(void *)(((u_int8_t *)ip) + off);
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	/* find the sassoc. */
	spi = esp->esp_spi;

	if ((sav = key_allocsa_extended(AF_INET,
									(caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst,
									IPPROTO_ESP, spi, interface)) == 0) {
		ipseclog((LOG_WARNING,
		    "IPv4 ESP input: no key association found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_nosa);
		goto bad;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP esp4_input called to allocate SA:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		ipseclog((LOG_DEBUG,
		    "IPv4 ESP input: non-mature/dying SA found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_badspi);
		goto bad;
	}
	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_DEBUG, "IPv4 ESP input: "
		    "unsupported encryption algorithm for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_badspi);
		goto bad;
	}

	/* check if we have proper ivlen information */
	ivlen = sav->ivlen;
	if (ivlen < 0) {
		ipseclog((LOG_ERR, "inproper ivlen in IPv4 ESP input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	seq = ntohl(((struct newesp *)esp)->esp_seq);

	/* Save ICV from packet for verification later */
	size_t siz = 0;
	unsigned char saved_icv[AH_MAXSUMSIZE];
	if (algo->finalizedecrypt) {
		siz = algo->icvlen;
		m_copydata(m, m->m_pkthdr.len - siz, siz, (caddr_t) saved_icv);
		goto delay_icv;
	}

	if (!((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay
	 && (sav->alg_auth && sav->key_auth)))
		goto noreplaycheck;

	if (sav->alg_auth == SADB_X_AALG_NULL ||
	    sav->alg_auth == SADB_AALG_NONE)
		goto noreplaycheck;

	/*
	 * check for sequence number.
	 */
	if (ipsec_chkreplay(seq, sav))
		; /*okey*/
	else {
		IPSEC_STAT_INCREMENT(ipsecstat.in_espreplay);
		ipseclog((LOG_WARNING,
		    "replay packet in IPv4 ESP input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		goto bad;
	}

	/* check ICV */
    {
	u_char sum0[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	u_char sum[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	const struct ah_algorithm *sumalgo;

	sumalgo = ah_algorithm_lookup(sav->alg_auth);
	if (!sumalgo)
		goto noreplaycheck;
	siz = (((*sumalgo->sumsiz)(sav) + 3) & ~(4 - 1));
	if (m->m_pkthdr.len < off + ESPMAXLEN + siz) {
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}
	if (AH_MAXSUMSIZE < siz) {
		ipseclog((LOG_DEBUG,
		    "internal error: AH_MAXSUMSIZE must be larger than %lu\n",
		    (u_int32_t)siz));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	m_copydata(m, m->m_pkthdr.len - siz, siz, (caddr_t) &sum0[0]);

	if (esp_auth(m, off, m->m_pkthdr.len - off - siz, sav, sum)) {
		ipseclog((LOG_WARNING, "auth fail in IPv4 ESP input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_espauthfail);
		goto bad;
	}

	if (cc_cmp_safe(siz, sum0, sum)) {
		ipseclog((LOG_WARNING, "cc_cmp fail in IPv4 ESP input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_espauthfail);
		goto bad;
	}

delay_icv:

	/* strip off the authentication data */
	m_adj(m, -siz);
	ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
	ip->ip_len = ip->ip_len - siz;
#else
	ip->ip_len = htons(ntohs(ip->ip_len) - siz);
#endif
	m->m_flags |= M_AUTHIPDGM;
	IPSEC_STAT_INCREMENT(ipsecstat.in_espauthsucc);
    }

	/*
	 * update sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_updatereplay(seq, sav)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_espreplay);
			goto bad;
		}
	}

noreplaycheck:

	/* process main esp header. */
	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		esplen = sizeof(struct esp);
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV)
			esplen = sizeof(struct esp);
		else
			esplen = sizeof(struct newesp);
	}

	if (m->m_pkthdr.len < off + esplen + ivlen + sizeof(esptail)) {
		ipseclog((LOG_WARNING,
		    "IPv4 ESP input: packet too short\n"));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	if (m->m_len < off + esplen + ivlen) {
		m = m_pullup(m, off + esplen + ivlen);
		if (!m) {
			ipseclog((LOG_DEBUG,
			    "IPv4 ESP input: can't pullup in esp4_input\n"));
			IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
			goto bad;
		}
	}

	/*
	 * pre-compute and cache intermediate key
	 */
	if (esp_schedule(algo, sav) != 0) {
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	/*
	 * decrypt the packet.
	 */
	if (!algo->decrypt)
		panic("internal error: no decrypt function");
	KERNEL_DEBUG(DBG_FNC_DECRYPT | DBG_FUNC_START, 0,0,0,0,0);
	if ((*algo->decrypt)(m, off, sav, algo, ivlen)) {
		/* m is already freed */
		m = NULL;
		ipseclog((LOG_ERR, "decrypt fail in IPv4 ESP input: %s\n",
		    ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		KERNEL_DEBUG(DBG_FNC_DECRYPT | DBG_FUNC_END, 1,0,0,0,0);
		goto bad;
	}
	KERNEL_DEBUG(DBG_FNC_DECRYPT | DBG_FUNC_END, 2,0,0,0,0);
	IPSEC_STAT_INCREMENT(ipsecstat.in_esphist[sav->alg_enc]);

	m->m_flags |= M_DECRYPTED;

	if (algo->finalizedecrypt)
        {
	    if ((*algo->finalizedecrypt)(sav, saved_icv, algo->icvlen)) {
		ipseclog((LOG_ERR, "packet decryption ICV failure\n"));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		KERNEL_DEBUG(DBG_FNC_DECRYPT | DBG_FUNC_END, 1,0,0,0,0);
		goto bad;
	    }
	}

	/*
	 * find the trailer of the ESP.
	 */
	m_copydata(m, m->m_pkthdr.len - sizeof(esptail), sizeof(esptail),
	     (caddr_t)&esptail);
	nxt = esptail.esp_nxt;
	taillen = esptail.esp_padlen + sizeof(esptail);

	if (m->m_pkthdr.len < taillen
	 || m->m_pkthdr.len - taillen < hlen) {	/*?*/
		ipseclog((LOG_WARNING,
		    "bad pad length in IPv4 ESP input: %s %s\n",
		    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}

	/* strip off the trailing pad area. */
	m_adj(m, -taillen);
	ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
	ip->ip_len = ip->ip_len - taillen;
#else
	ip->ip_len = htons(ntohs(ip->ip_len) - taillen);
#endif
	if (ip->ip_p == IPPROTO_UDP) {
		// offset includes the outer ip and udp header lengths.
		if (m->m_len < off) {
			m = m_pullup(m, off);
			if (!m) {
				ipseclog((LOG_DEBUG,
					  "IPv4 ESP input: invalid udp encapsulated ESP packet length \n"));
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}
		}

		// check the UDP encap header to detect changes in the source port, and then strip the header
		off -= sizeof(struct udphdr); // off no longer includes the udphdr's size
		// if peer is behind nat and this is the latest esp packet
		if ((sav->flags & SADB_X_EXT_NATT_DETECTED_PEER) != 0 &&
		    (sav->flags & SADB_X_EXT_OLD) == 0 &&
		    seq && sav->replay &&
		    seq >= sav->replay->lastseq)  {
			struct udphdr *encap_uh = (__typeof__(encap_uh))(void *)((caddr_t)ip + off);
			if (encap_uh->uh_sport &&
			    ntohs(encap_uh->uh_sport) != sav->remote_ike_port) {
				sav->remote_ike_port = ntohs(encap_uh->uh_sport);
			}
		}
		ip = esp4_input_strip_udp_encap(m, off);
		esp = (struct esp *)(void *)(((u_int8_t *)ip) + off);
	}

	/* was it transmitted over the IPsec tunnel SA? */
	if (ipsec4_tunnel_validate(m, off + esplen + ivlen, nxt, sav, &ifamily)) {
		ifaddr_t ifa;
		struct sockaddr_storage addr;

		/*
		 * strip off all the headers that precedes ESP header.
		 *	IP4 xx ESP IP4' payload -> IP4' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
		u_int8_t tos, otos;
		int sum;

		tos = ip->ip_tos;
		m_adj(m, off + esplen + ivlen);
		if (ifamily == AF_INET) {
			struct sockaddr_in *ipaddr;

			if (m->m_len < sizeof(*ip)) {
				m = m_pullup(m, sizeof(*ip));
				if (!m) {
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					goto bad;
				}
			}
			ip = mtod(m, struct ip *);
			/* ECN consideration. */

			otos = ip->ip_tos;
			if (ip_ecn_egress(ip4_ipsec_ecn, &tos, &ip->ip_tos) == 0) {
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			if (otos != ip->ip_tos) {
			    sum = ~ntohs(ip->ip_sum) & 0xffff;
			    sum += (~otos & 0xffff) + ip->ip_tos;
			    sum = (sum >> 16) + (sum & 0xffff);
			    sum += (sum >> 16);  /* add carry */
			    ip->ip_sum = htons(~sum & 0xffff);
			}

			if (!key_checktunnelsanity(sav, AF_INET,
			    (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst)) {
				ipseclog((LOG_ERR, "ipsec tunnel address mismatch "
			    "in ESP input: %s %s\n",
			    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			bzero(&addr, sizeof(addr));
			ipaddr = (__typeof__(ipaddr))&addr;
			ipaddr->sin_family = AF_INET;
			ipaddr->sin_len = sizeof(*ipaddr);
			ipaddr->sin_addr = ip->ip_dst;
#if INET6
		} else if (ifamily == AF_INET6) {
			struct sockaddr_in6 *ip6addr;

			/*
			 * m_pullup is prohibited in KAME IPv6 input processing
			 * but there's no other way!
			 */
			if (m->m_len < sizeof(*ip6)) {
				m = m_pullup(m, sizeof(*ip6));
				if (!m) {
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					goto bad;
				}
			}

			/*
			 * Expect 32-bit aligned data pointer on strict-align
			 * platforms.
			 */
			MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

			ip6 = mtod(m, struct ip6_hdr *);

			/* ECN consideration. */
			if (ip64_ecn_egress(ip4_ipsec_ecn, &tos, &ip6->ip6_flow) == 0) {
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			if (!key_checktunnelsanity(sav, AF_INET6,
			    (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst)) {
				ipseclog((LOG_ERR, "ipsec tunnel address mismatch "
			    "in ESP input: %s %s\n",
			    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			bzero(&addr, sizeof(addr));
			ip6addr = (__typeof__(ip6addr))&addr;
			ip6addr->sin6_family = AF_INET6;
			ip6addr->sin6_len = sizeof(*ip6addr);
			ip6addr->sin6_addr = ip6->ip6_dst;
#endif /* INET6 */
		} else {
			ipseclog((LOG_ERR, "ipsec tunnel unsupported address family "
				  "in ESP input\n"));
			goto bad;
		}

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_ESP, spi) != 0 ||
		    ipsec_addhist(m, IPPROTO_IPV4, 0) != 0) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_nomem);
			goto bad;
		}

		// update the receiving interface address based on the inner address
		ifa = ifa_ifwithaddr((struct sockaddr *)&addr);
		if (ifa) {
			m->m_pkthdr.rcvif = ifa->ifa_ifp;
			IFA_REMREF(ifa);
		}

		/* Clear the csum flags, they can't be valid for the inner headers */
		m->m_pkthdr.csum_flags = 0;

		// Input via IPSec interface
		if (sav->sah->ipsec_if != NULL) {
			// Return mbuf
			if (interface != NULL &&
				interface == sav->sah->ipsec_if) {
				out_m = m;
				goto done;
			}

			if (ipsec_inject_inbound_packet(sav->sah->ipsec_if, m) == 0) {
				m = NULL;
				goto done;
			} else {
				goto bad;
			}
		}
		
		if (proto_input(ifamily == AF_INET ? PF_INET : PF_INET6, m) != 0)
			goto bad;

		nxt = IPPROTO_DONE;
		KERNEL_DEBUG(DBG_FNC_ESPIN | DBG_FUNC_END, 2,0,0,0,0);
	} else {
		/*
		 * strip off ESP header and IV.
		 * even in m_pulldown case, we need to strip off ESP so that
		 * we can always compute checksum for AH correctly.
		 */
		size_t stripsiz;

		stripsiz = esplen + ivlen;

		ip = mtod(m, struct ip *);
		ovbcopy((caddr_t)ip, (caddr_t)(((u_char *)ip) + stripsiz), off);
		m->m_data += stripsiz;
		m->m_len -= stripsiz;
		m->m_pkthdr.len -= stripsiz;

		ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
		ip->ip_len = ip->ip_len - stripsiz;
#else
		ip->ip_len = htons(ntohs(ip->ip_len) - stripsiz);
#endif
		ip->ip_p = nxt;

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_ESP, spi) != 0) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_nomem);
			goto bad;
		}
		
		/*
		 * Set the csum valid flag, if we authenticated the
		 * packet, the payload shouldn't be corrupt unless
		 * it was corrupted before being signed on the other
		 * side.
		 */
		if (nxt == IPPROTO_TCP || nxt == IPPROTO_UDP) {
			m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
			m->m_pkthdr.csum_data = 0xFFFF;
			_CASSERT(offsetof(struct pkthdr, csum_data) == offsetof(struct pkthdr, csum_rx_val));
		}

		if (nxt != IPPROTO_DONE) {
			if ((ip_protox[nxt]->pr_flags & PR_LASTHDR) != 0 &&
			    ipsec4_in_reject(m, NULL)) {
				IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
				goto bad;
			}
			KERNEL_DEBUG(DBG_FNC_ESPIN | DBG_FUNC_END, 3,0,0,0,0);
			
			/* translate encapsulated UDP port ? */
			if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0)  {
				struct udphdr	*udp;
				
				if (nxt != IPPROTO_UDP)	{	/* not UPD packet - drop it */
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					goto bad;
				}
					
				if (m->m_len < off + sizeof(struct udphdr)) {
					m = m_pullup(m, off + sizeof(struct udphdr));
					if (!m) {
						ipseclog((LOG_DEBUG,
							"IPv4 ESP input: can't pullup UDP header in esp4_input\n"));
						IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
						goto bad;
					}
					ip = mtod(m, struct ip *);
				}
				udp = (struct udphdr *)(void *)(((u_int8_t *)ip) + off);
			
				lck_mtx_lock(sadb_mutex);
				if (sav->natt_encapsulated_src_port == 0) {	
					sav->natt_encapsulated_src_port = udp->uh_sport;
				} else if (sav->natt_encapsulated_src_port != udp->uh_sport) {	/* something wrong */
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					lck_mtx_unlock(sadb_mutex);
					goto bad;
				}
				lck_mtx_unlock(sadb_mutex);
				udp->uh_sport = htons(sav->remote_ike_port);
				udp->uh_sum = 0;
			}

			DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
                        	struct ip *, ip, struct ifnet *, m->m_pkthdr.rcvif,
                        	struct ip *, ip, struct ip6_hdr *, NULL);

			// Input via IPsec interface legacy path
			if (sav->sah->ipsec_if != NULL) {
				int mlen;
				if ((mlen = m_length2(m, NULL)) < hlen) {
					ipseclog((LOG_DEBUG,
						"IPv4 ESP input: decrypted packet too short %d < %d\n",
						mlen, hlen));
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					goto bad;
				}
				ip->ip_len = htons(ip->ip_len + hlen);
				ip->ip_off = htons(ip->ip_off);
				ip->ip_sum = 0;
				ip->ip_sum = ip_cksum_hdr_in(m, hlen);

				// Return mbuf
				if (interface != NULL &&
					interface == sav->sah->ipsec_if) {
					out_m = m;
					goto done;
				}

				if (ipsec_inject_inbound_packet(sav->sah->ipsec_if, m) == 0) {
					m = NULL;
					goto done;
				} else {
					goto bad;
				}
			}
			
			ip_proto_dispatch_in(m, off, nxt, 0);
		} else {
			m_freem(m);
		}
		m = NULL;
	}

done:
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP esp4_input call free SA:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
		key_freesav(sav, KEY_SADB_UNLOCKED);
	}
	IPSEC_STAT_INCREMENT(ipsecstat.in_success);
	return out_m;
bad:
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP esp4_input call free SA:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
		key_freesav(sav, KEY_SADB_UNLOCKED);
	}
	if (m) {
		m_freem(m);
	}
	KERNEL_DEBUG(DBG_FNC_ESPIN | DBG_FUNC_END, 4,0,0,0,0);
	return out_m;
}
#endif /* INET */

#if INET6

int
esp6_input(struct mbuf **mp, int *offp, int proto)
{
	return esp6_input_extended(mp, offp, proto, NULL);
}

int
esp6_input_extended(struct mbuf **mp, int *offp, int proto, ifnet_t interface)
{
#pragma unused(proto)
	struct mbuf *m = *mp;
	int off = *offp;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct esp *esp;
	struct esptail esptail;
	u_int32_t spi;
	u_int32_t seq;
	struct secasvar *sav = NULL;
	size_t taillen;
	u_int16_t nxt;
	char *nproto;
	const struct esp_algorithm *algo;
	int ivlen;
	size_t esplen;
	sa_family_t ifamily;

	/* sanity check for alignment. */
	if (off % 4 != 0 || m->m_pkthdr.len % 4 != 0) {
		ipseclog((LOG_ERR, "IPv6 ESP input: packet alignment problem "
			"(off=%d, pktlen=%d)\n", off, m->m_pkthdr.len));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, ESPMAXLEN, {return IPPROTO_DONE;});
	esp = (struct esp *)(void *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(esp, struct esp *, m, off, ESPMAXLEN);
	if (esp == NULL) {
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		return IPPROTO_DONE;
	}
#endif
	m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;

	/* Expect 32-bit data aligned pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip6 = mtod(m, struct ip6_hdr *);

	if (ntohs(ip6->ip6_plen) == 0) {
		ipseclog((LOG_ERR, "IPv6 ESP input: "
		    "ESP with IPv6 jumbogram is not supported.\n"));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

	nproto = ip6_get_prevhdr(m, off);
	if (nproto == NULL || (*nproto != IPPROTO_ESP &&
	    !(*nproto == IPPROTO_UDP && off >= sizeof(struct udphdr)))) {
		ipseclog((LOG_DEBUG, "IPv6 ESP input: invalid protocol type\n"));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

	/* find the sassoc. */
	spi = esp->esp_spi;

	if ((sav = key_allocsa_extended(AF_INET6,
									(caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst,
									IPPROTO_ESP, spi, interface)) == 0) {
		ipseclog((LOG_WARNING,
		    "IPv6 ESP input: no key association found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_nosa);
		goto bad;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP esp6_input called to allocate SA:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		ipseclog((LOG_DEBUG,
		    "IPv6 ESP input: non-mature/dying SA found for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_badspi);
		goto bad;
	}
	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_DEBUG, "IPv6 ESP input: "
		    "unsupported encryption algorithm for spi %u\n",
		    (u_int32_t)ntohl(spi)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_badspi);
		goto bad;
	}

	/* check if we have proper ivlen information */
	ivlen = sav->ivlen;
	if (ivlen < 0) {
		ipseclog((LOG_ERR, "inproper ivlen in IPv6 ESP input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_badspi);
		goto bad;
	}

	seq = ntohl(((struct newesp *)esp)->esp_seq);

	/* Save ICV from packet for verification later */
	size_t siz = 0;
	unsigned char saved_icv[AH_MAXSUMSIZE];
	if (algo->finalizedecrypt) {
		siz = algo->icvlen;
		m_copydata(m, m->m_pkthdr.len - siz, siz, (caddr_t) saved_icv);
		goto delay_icv;
	}

	if (!((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay
	 && (sav->alg_auth && sav->key_auth)))
		goto noreplaycheck;

	if (sav->alg_auth == SADB_X_AALG_NULL ||
	    sav->alg_auth == SADB_AALG_NONE)
		goto noreplaycheck;

	/*
	 * check for sequence number.
	 */
	if (ipsec_chkreplay(seq, sav))
		; /*okey*/
	else {
		IPSEC_STAT_INCREMENT(ipsec6stat.in_espreplay);
		ipseclog((LOG_WARNING,
		    "replay packet in IPv6 ESP input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		goto bad;
	}

	/* check ICV */
    {
	u_char sum0[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	u_char sum[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	const struct ah_algorithm *sumalgo;

	sumalgo = ah_algorithm_lookup(sav->alg_auth);
	if (!sumalgo)
		goto noreplaycheck;
	siz = (((*sumalgo->sumsiz)(sav) + 3) & ~(4 - 1));
	if (m->m_pkthdr.len < off + ESPMAXLEN + siz) {
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		goto bad;
	}
	if (AH_MAXSUMSIZE < siz) {
		ipseclog((LOG_DEBUG,
		    "internal error: AH_MAXSUMSIZE must be larger than %lu\n",
		    (u_int32_t)siz));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

	m_copydata(m, m->m_pkthdr.len - siz, siz, (caddr_t) &sum0[0]);

	if (esp_auth(m, off, m->m_pkthdr.len - off - siz, sav, sum)) {
		ipseclog((LOG_WARNING, "auth fail in IPv6 ESP input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_espauthfail);
		goto bad;
	}

	if (cc_cmp_safe(siz, sum0, sum)) {
		ipseclog((LOG_WARNING, "auth fail in IPv6 ESP input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_espauthfail);
		goto bad;
	}

delay_icv:

	/* strip off the authentication data */
	m_adj(m, -siz);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - siz);

	m->m_flags |= M_AUTHIPDGM;
	IPSEC_STAT_INCREMENT(ipsec6stat.in_espauthsucc);
    }

	/*
	 * update sequence number.
	 */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay) {
		if (ipsec_updatereplay(seq, sav)) {
			IPSEC_STAT_INCREMENT(ipsec6stat.in_espreplay);
			goto bad;
		}
	}

noreplaycheck:

	/* process main esp header. */
	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		esplen = sizeof(struct esp);
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV)
			esplen = sizeof(struct esp);
		else
			esplen = sizeof(struct newesp);
	}

	if (m->m_pkthdr.len < off + esplen + ivlen + sizeof(esptail)) {
		ipseclog((LOG_WARNING,
		    "IPv6 ESP input: packet too short\n"));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, esplen + ivlen, return IPPROTO_DONE);	/*XXX*/
#else
	IP6_EXTHDR_GET(esp, struct esp *, m, off, esplen + ivlen);
	if (esp == NULL) {
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		m = NULL;
		goto bad;
	}
#endif
	ip6 = mtod(m, struct ip6_hdr *);	/*set it again just in case*/

	/*
	 * pre-compute and cache intermediate key
	 */
	if (esp_schedule(algo, sav) != 0) {
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

	/*
	 * decrypt the packet.
	 */
	if (!algo->decrypt)
		panic("internal error: no decrypt function");
	if ((*algo->decrypt)(m, off, sav, algo, ivlen)) {
		/* m is already freed */
		m = NULL;
		ipseclog((LOG_ERR, "decrypt fail in IPv6 ESP input: %s\n",
		    ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}
	IPSEC_STAT_INCREMENT(ipsec6stat.in_esphist[sav->alg_enc]);

	m->m_flags |= M_DECRYPTED;

	if (algo->finalizedecrypt)
        {
	    if ((*algo->finalizedecrypt)(sav, saved_icv, algo->icvlen)) {
		ipseclog((LOG_ERR, "packet decryption ICV failure\n"));
		IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
		KERNEL_DEBUG(DBG_FNC_DECRYPT | DBG_FUNC_END, 1,0,0,0,0);
		goto bad;
	    }
	}

	/*
	 * find the trailer of the ESP.
	 */
	m_copydata(m, m->m_pkthdr.len - sizeof(esptail), sizeof(esptail),
	     (caddr_t)&esptail);
	nxt = esptail.esp_nxt;
	taillen = esptail.esp_padlen + sizeof(esptail);

	if (m->m_pkthdr.len < taillen
	 || m->m_pkthdr.len - taillen < sizeof(struct ip6_hdr)) {	/*?*/
		ipseclog((LOG_WARNING,
		    "bad pad length in IPv6 ESP input: %s %s\n",
		    ipsec6_logpacketstr(ip6, spi), ipsec_logsastr(sav)));
		IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
		goto bad;
	}

	/* strip off the trailing pad area. */
	m_adj(m, -taillen);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - taillen);

	if (*nproto == IPPROTO_UDP) {
		// offset includes the outer ip and udp header lengths.
		if (m->m_len < off) {
			m = m_pullup(m,  off);
			if (!m) {
				ipseclog((LOG_DEBUG,
					"IPv6 ESP input: invalid udp encapsulated ESP packet length\n"));
				IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
				goto bad;
			}
		}

		// check the UDP encap header to detect changes in the source port, and then strip the header
		off -= sizeof(struct udphdr); // off no longer includes the udphdr's size
		// if peer is behind nat and this is the latest esp packet
		if ((sav->flags & SADB_X_EXT_NATT_DETECTED_PEER) != 0 &&
		    (sav->flags & SADB_X_EXT_OLD) == 0 &&
		    seq && sav->replay &&
		    seq >= sav->replay->lastseq)  {
			struct udphdr *encap_uh = (__typeof__(encap_uh))(void *)((caddr_t)ip6 + off);
			if (encap_uh->uh_sport &&
			    ntohs(encap_uh->uh_sport) != sav->remote_ike_port) {
				sav->remote_ike_port = ntohs(encap_uh->uh_sport);
			}
		}
		ip6 = esp6_input_strip_udp_encap(m, off);
		esp = (struct esp *)(void *)(((u_int8_t *)ip6) + off);
	}


	/* was it transmitted over the IPsec tunnel SA? */
	if (ipsec6_tunnel_validate(m, off + esplen + ivlen, nxt, sav, &ifamily)) {
		ifaddr_t ifa;
		struct sockaddr_storage addr;

		/*
		 * strip off all the headers that precedes ESP header.
		 *	IP6 xx ESP IP6' payload -> IP6' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
		u_int32_t flowinfo;	/*net endian*/
		flowinfo = ip6->ip6_flow;
		m_adj(m, off + esplen + ivlen);
		if (ifamily == AF_INET6) {
			struct sockaddr_in6 *ip6addr;

			if (m->m_len < sizeof(*ip6)) {
#ifndef PULLDOWN_TEST
				/*
				 * m_pullup is prohibited in KAME IPv6 input processing
				 * but there's no other way!
				 */
#else
				/* okay to pullup in m_pulldown style */
#endif
				m = m_pullup(m, sizeof(*ip6));
				if (!m) {
					IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
					goto bad;
				}
			}
			ip6 = mtod(m, struct ip6_hdr *);
			/* ECN consideration. */
			if (ip6_ecn_egress(ip6_ipsec_ecn, &flowinfo, &ip6->ip6_flow) == 0) {
				IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
				goto bad;
			}
			if (!key_checktunnelsanity(sav, AF_INET6,
				    (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst)) {
				ipseclog((LOG_ERR, "ipsec tunnel address mismatch "
				    "in IPv6 ESP input: %s %s\n",
				    ipsec6_logpacketstr(ip6, spi),
				    ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(ipsec6stat.in_inval);
				goto bad;
			}

			bzero(&addr, sizeof(addr));
			ip6addr = (__typeof__(ip6addr))&addr;
			ip6addr->sin6_family = AF_INET6;
			ip6addr->sin6_len = sizeof(*ip6addr);
			ip6addr->sin6_addr = ip6->ip6_dst;
		} else if (ifamily == AF_INET) {
			struct sockaddr_in *ipaddr;

			if (m->m_len < sizeof(*ip)) {
				m = m_pullup(m, sizeof(*ip));
				if (!m) {
					IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
					goto bad;
				}
			}

			u_int8_t otos;
			int sum;

			ip = mtod(m, struct ip *);
			otos = ip->ip_tos;
			/* ECN consideration. */
			if (ip46_ecn_egress(ip6_ipsec_ecn, &flowinfo, &ip->ip_tos) == 0) {
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			if (otos != ip->ip_tos) {
			    sum = ~ntohs(ip->ip_sum) & 0xffff;
			    sum += (~otos & 0xffff) + ip->ip_tos;
			    sum = (sum >> 16) + (sum & 0xffff);
			    sum += (sum >> 16);  /* add carry */
			    ip->ip_sum = htons(~sum & 0xffff);
			}

			if (!key_checktunnelsanity(sav, AF_INET,
			    (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst)) {
				ipseclog((LOG_ERR, "ipsec tunnel address mismatch "
			    "in ESP input: %s %s\n",
			    ipsec4_logpacketstr(ip, spi), ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
				goto bad;
			}

			bzero(&addr, sizeof(addr));
			ipaddr = (__typeof__(ipaddr))&addr;
			ipaddr->sin_family = AF_INET;
			ipaddr->sin_len = sizeof(*ipaddr);
			ipaddr->sin_addr = ip->ip_dst;
		}

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_ESP, spi) != 0 || 
		    ipsec_addhist(m, IPPROTO_IPV6, 0) != 0) {
			IPSEC_STAT_INCREMENT(ipsec6stat.in_nomem);
			goto bad;
		}

		// update the receiving interface address based on the inner address
		ifa = ifa_ifwithaddr((struct sockaddr *)&addr);
		if (ifa) {
			m->m_pkthdr.rcvif = ifa->ifa_ifp;
			IFA_REMREF(ifa);
		}

		// Input via IPSec interface
		if (sav->sah->ipsec_if != NULL) {
			// Return mbuf
			if (interface != NULL &&
				interface == sav->sah->ipsec_if) {
				goto done;
			}

			if (ipsec_inject_inbound_packet(sav->sah->ipsec_if, m) == 0) {
				m = NULL;
				nxt = IPPROTO_DONE;
				goto done;
			} else {
				goto bad;
			}
		}
		
		if (proto_input(ifamily == AF_INET ? PF_INET : PF_INET6, m) != 0)
			goto bad;
		nxt = IPPROTO_DONE;
	} else {
		/*
		 * strip off ESP header and IV.
		 * even in m_pulldown case, we need to strip off ESP so that
		 * we can always compute checksum for AH correctly.
		 */
		size_t stripsiz;
		char *prvnxtp;

		/*
		 * Set the next header field of the previous header correctly.
		 */
		prvnxtp = ip6_get_prevhdr(m, off); /* XXX */
		*prvnxtp = nxt;

		stripsiz = esplen + ivlen;

		ip6 = mtod(m, struct ip6_hdr *);
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
				goto bad;
			}
			m_adj(n, stripsiz);
			/* m_cat does not update m_pkthdr.len */
			m->m_pkthdr.len += n->m_pkthdr.len;
			m_cat(m, n);
		}

#ifndef PULLDOWN_TEST
		/*
		 * KAME requires that the packet to be contiguous on the
		 * mbuf.  We need to make that sure.
		 * this kind of code should be avoided.
		 * XXX other conditions to avoid running this part?
		 */
		if (m->m_len != m->m_pkthdr.len) {
			struct mbuf *n = NULL;
			int maxlen;

			MGETHDR(n, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
			maxlen = MHLEN;
			if (n)
				M_COPY_PKTHDR(n, m);
			if (n && m->m_pkthdr.len > maxlen) {
				MCLGET(n, M_DONTWAIT);
				maxlen = MCLBYTES;
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (!n) {
				printf("esp6_input: mbuf allocation failed\n");
				goto bad;
			}

			if (m->m_pkthdr.len <= maxlen) {
				m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
				n->m_len = m->m_pkthdr.len;
				n->m_pkthdr.len = m->m_pkthdr.len;
				n->m_next = NULL;
				m_freem(m);
			} else {
				m_copydata(m, 0, maxlen, mtod(n, caddr_t));
				n->m_len = maxlen;
				n->m_pkthdr.len = m->m_pkthdr.len;
				n->m_next = m;
				m_adj(m, maxlen);
				m->m_flags &= ~M_PKTHDR;
			}
			m = n;
		}
#endif

		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - stripsiz);

		key_sa_recordxfer(sav, m);
		if (ipsec_addhist(m, IPPROTO_ESP, spi) != 0) {
			IPSEC_STAT_INCREMENT(ipsec6stat.in_nomem);
			goto bad;
		}

		/*
		 * Set the csum valid flag, if we authenticated the
		 * packet, the payload shouldn't be corrupt unless
		 * it was corrupted before being signed on the other
		 * side.
		 */
		if (nxt == IPPROTO_TCP || nxt == IPPROTO_UDP) {
			m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
			m->m_pkthdr.csum_data = 0xFFFF;
			_CASSERT(offsetof(struct pkthdr, csum_data) == offsetof(struct pkthdr, csum_rx_val));
		}

		// Input via IPSec interface
		if (sav->sah->ipsec_if != NULL) {
			// Return mbuf
			if (interface != NULL &&
				interface == sav->sah->ipsec_if) {
				goto done;
			}

			if (ipsec_inject_inbound_packet(sav->sah->ipsec_if, m) == 0) {
				m = NULL;
				nxt = IPPROTO_DONE;
				goto done;
			} else {
				goto bad;
			}
		}
		
	}

done:
	*offp = off;
	*mp = m;
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP esp6_input call free SA:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
		key_freesav(sav, KEY_SADB_UNLOCKED);
	}
	IPSEC_STAT_INCREMENT(ipsec6stat.in_success);
	return nxt;

bad:
	if (sav) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP esp6_input call free SA:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sav)));
		key_freesav(sav, KEY_SADB_UNLOCKED);
	}
	if (m) {
		m_freem(m);
	}
	if (interface != NULL) {
		*mp = NULL;
	}
	return IPPROTO_DONE;
}

void
esp6_ctlinput(int cmd, struct sockaddr *sa, void *d, __unused struct ifnet *ifp)
{
	const struct newesp *espp;
	struct newesp esp;
	struct ip6ctlparam *ip6cp = NULL, ip6cp1;
	struct secasvar *sav;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int off = 0;
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
		 * Notify the error to all possible sockets via pfctlinput2.
		 * Since the upper layer information (such as protocol type,
		 * source and destination ports) is embedded in the encrypted
		 * data and might have been cut, we can't directly call
		 * an upper layer ctlinput function. However, the pcbnotify
		 * function will consider source and destination addresses
		 * as well as the flow info value, and may be able to find
		 * some PCB that should be notified.
		 * Although pfctlinput2 will call esp6_ctlinput(), there is
		 * no possibility of an infinite loop of function calls,
		 * because we don't pass the inner IPv6 header.
		 */
		bzero(&ip6cp1, sizeof(ip6cp1));
		ip6cp1.ip6c_src = ip6cp->ip6c_src;
		pfctlinput2(cmd, sa, (void *)&ip6cp1);

		/*
		 * Then go to special cases that need ESP header information.
		 * XXX: We assume that when ip6 is non NULL,
		 * M and OFF are valid.
		 */

		/* check if we can safely examine src and dst ports */
		if (m->m_pkthdr.len < off + sizeof(esp))
			return;

		if (m->m_len < off + sizeof(esp)) {
			/*
			 * this should be rare case,
			 * so we compromise on this copy...
			 */
			m_copydata(m, off, sizeof(esp), (caddr_t)&esp);
			espp = &esp;
		} else
			espp = (struct newesp*)(void *)(mtod(m, caddr_t) + off);

		if (cmd == PRC_MSGSIZE) {
			int valid = 0;

			/*
			 * Check to see if we have a valid SA corresponding to
			 * the address in the ICMP message payload.
			 */
			sa6_src = ip6cp->ip6c_src;
			sa6_dst = (struct sockaddr_in6 *)(void *)sa;
			sav = key_allocsa(AF_INET6,
					  (caddr_t)&sa6_src->sin6_addr,
					  (caddr_t)&sa6_dst->sin6_addr,
					  IPPROTO_ESP, espp->esp_spi);
			if (sav) {
				if (sav->state == SADB_SASTATE_MATURE ||
				    sav->state == SADB_SASTATE_DYING)
					valid++;
				key_freesav(sav, KEY_SADB_UNLOCKED);
			}

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
	} else {
		/* we normally notify any pcb here */
	}
}
#endif /* INET6 */
