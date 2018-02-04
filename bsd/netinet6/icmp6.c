/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/icmp6.c,v 1.6.2.6 2001/07/10 09:44:16 ume Exp $	*/
/*	$KAME: icmp6.c,v 1.211 2001/04/04 05:56:20 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mcache.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/domain.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6_var.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#include <net/net_osdep.h>

#if NECP
#include <net/necp.h>
#endif

extern struct ip6protosw *ip6_protox[];

extern uint32_t rip_sendspace;
extern uint32_t rip_recvspace;

struct icmp6stat icmp6stat;

extern struct inpcbhead ripcb;
extern int icmp6errppslim;
extern int icmp6rappslim;
static int icmp6errpps_count = 0;
static int icmp6rapps_count = 0;
static struct timeval icmp6errppslim_last;
static struct timeval icmp6rappslim_last;
extern int icmp6_nodeinfo;
extern struct inpcbinfo ripcbinfo;

static void icmp6_errcount(struct icmp6errstat *, int, int);
static int icmp6_rip6_input(struct mbuf **, int);
static int icmp6_ratelimit(const struct in6_addr *, const int, const int);
static const char *icmp6_redirect_diag(struct in6_addr *,
	struct in6_addr *, struct in6_addr *);
static struct mbuf *ni6_input(struct mbuf *, int);
static struct mbuf *ni6_nametodns(const char *, int, int);
static int ni6_dnsmatch(const char *, int, const char *, int);
static int ni6_addrs(struct icmp6_nodeinfo *,
			  struct ifnet **, char *);
static int ni6_store_addrs(struct icmp6_nodeinfo *, struct icmp6_nodeinfo *,
				struct ifnet *, int);
static int icmp6_notify_error(struct mbuf *, int, int, int);



void
icmp6_init(struct ip6protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int icmp6_initialized = 0;

	/* Also called from ip6_init() without pp */
	VERIFY(pp == NULL ||
	    (pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	/* This gets called by more than one protocols, so initialize once */
	if (!icmp6_initialized) {
		icmp6_initialized = 1;
		mld_init();
	}
}

static void
icmp6_errcount(struct icmp6errstat *stat, int type, int code)
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			stat->icp6errs_dst_unreach_noroute++;
			return;
		case ICMP6_DST_UNREACH_ADMIN:
			stat->icp6errs_dst_unreach_admin++;
			return;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			stat->icp6errs_dst_unreach_beyondscope++;
			return;
		case ICMP6_DST_UNREACH_ADDR:
			stat->icp6errs_dst_unreach_addr++;
			return;
		case ICMP6_DST_UNREACH_NOPORT:
			stat->icp6errs_dst_unreach_noport++;
			return;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		stat->icp6errs_packet_too_big++;
		return;
	case ICMP6_TIME_EXCEEDED:
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			stat->icp6errs_time_exceed_transit++;
			return;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			stat->icp6errs_time_exceed_reassembly++;
			return;
		}
		break;
	case ICMP6_PARAM_PROB:
		switch (code) {
		case ICMP6_PARAMPROB_HEADER:
			stat->icp6errs_paramprob_header++;
			return;
		case ICMP6_PARAMPROB_NEXTHEADER:
			stat->icp6errs_paramprob_nextheader++;
			return;
		case ICMP6_PARAMPROB_OPTION:
			stat->icp6errs_paramprob_option++;
			return;
		}
		break;
	case ND_REDIRECT:
		stat->icp6errs_redirect++;
		return;
	}
	stat->icp6errs_unknown++;
}

/*
 * A wrapper function for icmp6_error() necessary when the erroneous packet
 * may not contain enough scope zone information.
 */
void
icmp6_error2(struct mbuf *m, int type, int code, int param,
    struct ifnet *ifp)
{
	struct ip6_hdr *ip6;

	if (ifp == NULL)
		return;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, 0, sizeof(struct ip6_hdr),return );
#else
	if (m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return;
	}
#endif

	ip6 = mtod(m, struct ip6_hdr *);

	if (in6_setscope(&ip6->ip6_src, ifp, NULL) != 0)
		return;
	if (in6_setscope(&ip6->ip6_dst, ifp, NULL) != 0)
		return;

	icmp6_error(m, type, code, param);
}

/*
 * Generate an error packet of type error in response to bad IP6 packet.
 */
void
icmp6_error(struct mbuf *m, int type, int code, int param) {
	icmp6_error_flag(m, type, code, param, ICMP6_ERROR_RST_MRCVIF);
}

void icmp6_error_flag (struct mbuf *m, int type, int code, int param, int flags)
{
	struct ip6_hdr *oip6, *nip6;
	struct icmp6_hdr *icmp6;
	u_int preplen;
	int off;
	int nxt;

	icmp6stat.icp6s_error++;

	/* count per-type-code statistics */
	icmp6_errcount(&icmp6stat.icp6s_outerrhist, type, code);

#ifdef M_DECRYPTED	/*not openbsd*/
	if (m->m_flags & M_DECRYPTED) {
		icmp6stat.icp6s_canterror++;
		goto freeit;
	}
#endif

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, 0, sizeof(struct ip6_hdr), return);
#else
	if (m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return;
	}
#endif
	oip6 = mtod(m, struct ip6_hdr *);

	/*
	 * If the destination address of the erroneous packet is a multicast
	 * address, or the packet was sent using link-layer multicast,
	 * we should basically suppress sending an error (RFC 2463, Section
	 * 2.4).
	 * We have two exceptions (the item e.2 in that section):
	 * - the Pakcet Too Big message can be sent for path MTU discovery.
	 * - the Parameter Problem Message that can be allowed an icmp6 error
	 *   in the option type field.  This check has been done in
	 *   ip6_unknown_opt(), so we can just check the type and code.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST) ||
	     IN6_IS_ADDR_MULTICAST(&oip6->ip6_dst)) &&
	    (type != ICMP6_PACKET_TOO_BIG &&
	     (type != ICMP6_PARAM_PROB ||
	      code != ICMP6_PARAMPROB_OPTION)))
		goto freeit;

	/*
	 * RFC 2463, 2.4 (e.5): source address check.
	 * XXX: the case of anycast source?
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&oip6->ip6_src) ||
	    IN6_IS_ADDR_MULTICAST(&oip6->ip6_src))
		goto freeit;

	/*
	 * If we are about to send ICMPv6 against ICMPv6 error/redirect,
	 * don't do it.
	 */
	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off >= 0 && nxt == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icp;

#ifndef PULLDOWN_TEST
		IP6_EXTHDR_CHECK(m, 0, off + sizeof(struct icmp6_hdr), return);
		icp = (struct icmp6_hdr *)(mtod(m, caddr_t) + off);
#else
		IP6_EXTHDR_GET(icp, struct icmp6_hdr *, m, off,
			sizeof(*icp));
		if (icp == NULL) {
			icmp6stat.icp6s_tooshort++;
			return;
		}
#endif
		if (icp->icmp6_type < ICMP6_ECHO_REQUEST ||
		    icp->icmp6_type == ND_REDIRECT) {
			/*
			 * ICMPv6 error
			 * Special case: for redirect (which is
			 * informational) we must not send icmp6 error.
			 */
			icmp6stat.icp6s_canterror++;
			goto freeit;
		} else {
			/* ICMPv6 informational - send the error */
		}
	} else {
		/* non-ICMPv6 - send the error */
	}

	oip6 = mtod(m, struct ip6_hdr *); /* adjust pointer */

	/* Finally, do rate limitation check. */
	if (icmp6_ratelimit(&oip6->ip6_src, type, code)) {
		icmp6stat.icp6s_toofreq++;
		goto freeit;
	}

	/*
	 * OK, ICMP6 can be generated.
	 */

	if (m->m_pkthdr.len >= ICMPV6_PLD_MAXLEN)
		m_adj(m, ICMPV6_PLD_MAXLEN - m->m_pkthdr.len);

	preplen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	M_PREPEND(m, preplen, M_DONTWAIT, 1);
	if (m && m->m_len < preplen)
		m = m_pullup(m, preplen);
	if (m == NULL) {
		nd6log((LOG_DEBUG, "ENOBUFS in icmp6_error %d\n", __LINE__));
		return;
	}

	nip6 = mtod(m, struct ip6_hdr *);
	nip6->ip6_src  = oip6->ip6_src;
	nip6->ip6_dst  = oip6->ip6_dst;

	in6_clearscope(&oip6->ip6_src);
	in6_clearscope(&oip6->ip6_dst);

	icmp6 = (struct icmp6_hdr *)(nip6 + 1);
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = code;
	icmp6->icmp6_pptr = htonl((u_int32_t)param);

	/*
	 * icmp6_reflect() is designed to be in the input path.
	 * icmp6_error() can be called from both input and output path,
	 * and if we are in output path rcvif could contain bogus value.
	 * clear m->m_pkthdr.rcvif for safety, we should have enough scope
	 * information in ip header (nip6).
	 */
	if (flags & ICMP6_ERROR_RST_MRCVIF) {
		m->m_pkthdr.rcvif = NULL;
	}

	icmp6stat.icp6s_outhist[type]++;
	icmp6_reflect(m, sizeof(struct ip6_hdr)); /* header order: IPv6 - ICMPv6 */

	return;

  freeit:
	/*
	 * If we can't tell whether or not we can generate ICMP6, free it.
	 */
	m_freem(m);
}

/*
 * Process a received ICMP6 message.
 */
int
icmp6_input(struct mbuf **mp, int *offp, int proto)
{
#pragma unused(proto)
	struct mbuf *m = *mp, *n;
	struct ifnet *ifp;
	struct ip6_hdr *ip6, *nip6;
	struct icmp6_hdr *icmp6, *nicmp6;
	int off = *offp;
	int icmp6len = m->m_pkthdr.len - *offp;
	int code, sum, noff, proxy = 0;

	ifp = m->m_pkthdr.rcvif;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(struct icmp6_hdr), return IPPROTO_DONE);
	/* m might change if M_LOOP.  So, call mtod after this */
#endif

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	/*
	 * Locate icmp6 structure in mbuf, and check
	 * that not corrupted and of at least minimum length
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	if (icmp6len < sizeof(struct icmp6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		goto freeit;
	}

#ifndef PULLDOWN_TEST
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		return IPPROTO_DONE;
	}
#endif
	code = icmp6->icmp6_code;

	/*
	 * Early check for RFC 6980
	 * Drop certain NDP packets if they came in fragmented
	 */
	switch (icmp6->icmp6_type) {
	case ND_ROUTER_SOLICIT:
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_REDIRECT:
		if (m->m_pkthdr.pkt_flags & PKTF_REASSEMBLED) {
			icmp6stat.icp6s_rfc6980_drop++;
			goto freeit;
		}
		break;
	default:
		break;
	}

	/* Apply rate limit before checksum validation. */
	if (icmp6_ratelimit(&ip6->ip6_dst, icmp6->icmp6_type, code)) {
		icmp6stat.icp6s_toofreq++;
		goto freeit;
	}

	/*
	 * Check multicast group membership.
	 * Note: SSM filters are not applied for ICMPv6 traffic.
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct in6_multi	*inm;

		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&ip6->ip6_dst, ifp, inm);
		in6_multihead_lock_done();

		if (inm == NULL) {
			/*
			 * Don't discard if this is a Neighbor Solicitation
			 * that needs to be proxied (see check down below.)
			 */
			if (!(m->m_pkthdr.pkt_flags & PKTF_PROXY_DST)) {
				ip6stat.ip6s_notmember++;
				in6_ifstat_inc(m->m_pkthdr.rcvif,
				    ifs6_in_discard);
				goto freeit;
			}
		} else {
			IN6M_REMREF(inm);
		}
	}

	/*
	 * calculate the checksum
	 */
	if ((sum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len)) != 0) {
		nd6log((LOG_ERR,
		    "ICMP6 checksum error(%d|%x) %s\n",
		    icmp6->icmp6_type, sum, ip6_sprintf(&ip6->ip6_src)));
		icmp6stat.icp6s_checksum++;
		goto freeit;
	}

	if (m->m_pkthdr.pkt_flags & PKTF_PROXY_DST) {
		/*
		 * This is the special case of proxying NS (dst is either
		 * solicited-node multicast or unicast); process it locally
		 * but don't deliver it to sockets.  It practically lets us
		 * steer the packet to nd6_prproxy_ns_input, where more
		 * specific tests and actions will be taken.
		 */
		switch (icmp6->icmp6_type) {
		case ND_NEIGHBOR_SOLICIT:
			proxy = 1;
			break;
		default:
			goto freeit;
		}
	}

	icmp6stat.icp6s_inhist[icmp6->icmp6_type]++;
	icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_msg);
	if (icmp6->icmp6_type < ICMP6_INFOMSG_MASK)
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_error);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_dstunreach);
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_ADDR:	/* PRC_HOSTDEAD is a DOS */
			code = PRC_UNREACH_NET;
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_adminprohib);
			code = PRC_UNREACH_PROTOCOL; /* is this a good code? */
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			/* I mean "source address was incorrect." */
			code = PRC_PARAMPROB;
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			code = PRC_UNREACH_PORT;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PACKET_TOO_BIG:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_pkttoobig);

		code = PRC_MSGSIZE;

		/*
		 * Updating the path MTU will be done after examining
		 * intermediate extension headers.
		 */
		goto deliver;

	case ICMP6_TIME_EXCEEDED:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_timeexceed);
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			code = PRC_TIMXCEED_INTRANS;
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			code = PRC_TIMXCEED_REASS;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PARAM_PROB:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_paramprob);
		switch (code) {
		case ICMP6_PARAMPROB_NEXTHEADER:
			code = PRC_UNREACH_PROTOCOL;
			break;
		case ICMP6_PARAMPROB_HEADER:
		case ICMP6_PARAMPROB_OPTION:
			code = PRC_PARAMPROB;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_ECHO_REQUEST:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_echo);
		if (code != 0)
			goto badcode;

		if ((n = m_copy(m, 0, M_COPYALL)) == NULL) {
			/* Give up remote */
			goto rate_limit_checked;
		}
		if ((n->m_flags & M_EXT) != 0
		 || n->m_len < off + sizeof(struct icmp6_hdr)) {
			struct mbuf *n0 = n;
			const int maxlen = sizeof(*nip6) + sizeof(*nicmp6);

			/*
			 * Prepare an internal mbuf. m_pullup() doesn't
			 * always copy the length we specified.
			 */
			if (maxlen >= MCLBYTES) {
				/* Give up remote */
				m_freem(n0);
				goto rate_limit_checked;
			}
			MGETHDR(n, M_DONTWAIT, n0->m_type);	/* MAC-OK */
			if (n && maxlen >= MHLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				/* Give up remote */
				m_freem(n0);
				goto rate_limit_checked;
			}
			M_COPY_PKTHDR(n, n0);
			/*
			 * Copy IPv6 and ICMPv6 only.
			 */
			nip6 = mtod(n, struct ip6_hdr *);
			bcopy(ip6, nip6, sizeof(struct ip6_hdr));
			nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
			bcopy(icmp6, nicmp6, sizeof(struct icmp6_hdr));
			noff = sizeof(struct ip6_hdr);
			n->m_pkthdr.len = n->m_len =
				noff + sizeof(struct icmp6_hdr);
			/*
			 * Adjust mbuf. ip6_plen will be adjusted in
			 * ip6_output().
			 */
			m_adj(n0, off + sizeof(struct icmp6_hdr));
			n->m_pkthdr.len += n0->m_pkthdr.len;
			n->m_next = n0;
			n0->m_flags &= ~M_PKTHDR;
		} else {
			nip6 = mtod(n, struct ip6_hdr *);
			IP6_EXTHDR_GET(nicmp6, struct icmp6_hdr *, n, off,
				sizeof(*nicmp6));
			noff = off;
		}
		if(nicmp6 == NULL)
			panic("nicmp6 is NULL in %s, which isn't good!\n", __FUNCTION__);
		else {
			nicmp6->icmp6_type = ICMP6_ECHO_REPLY;
			nicmp6->icmp6_code = 0;
		}
		if (n) {
			icmp6stat.icp6s_reflect++;
			icmp6stat.icp6s_outhist[ICMP6_ECHO_REPLY]++;
			icmp6_reflect(n, noff);
		}
		goto rate_limit_checked;

	case ICMP6_ECHO_REPLY:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_echoreply);
		if (code != 0)
			goto badcode;
		break;

	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:

		if (icmp6len < sizeof(struct mld_hdr))
			goto badlen;
		if (icmp6->icmp6_type == MLD_LISTENER_QUERY) /* XXX: ugly... */
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mldquery);
		else
			icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mldreport);

		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			if (mld_input(m, off, icmp6len) == IPPROTO_DONE)
				m = NULL;
			goto freeit;
		}
		if (mld_input(n, off, icmp6len) != IPPROTO_DONE)
			m_freem(n);
		/* m stays. */
		goto rate_limit_checked;

	case MLD_LISTENER_DONE:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mlddone);
		if (icmp6len < sizeof(struct mld_hdr))	/* necessary? */
			goto badlen;
		break;		/* nothing to be done in kernel */

	case MLD_MTRACE_RESP:
	case MLD_MTRACE:
		/* XXX: these two are experimental.  not officially defined. */
		/* XXX: per-interface statistics? */
		break;		/* just pass it to applications */

	case ICMP6_NI_QUERY:
		if (!icmp6_nodeinfo)
			break;
//### LD 10/20 Check fbsd differences here. Not sure we're more advanced or not.
		/* By RFC 4620 refuse to answer queries from global scope addresses */
		if ((icmp6_nodeinfo & 8) != 8 && in6_addrscope(&ip6->ip6_src) == IPV6_ADDR_SCOPE_GLOBAL)
			break;

		if (icmp6len < sizeof(struct icmp6_nodeinfo))
			goto badlen;

#ifndef PULLDOWN_TEST
		IP6_EXTHDR_CHECK(m, off, sizeof(struct icmp6_nodeinfo),
				 return IPPROTO_DONE);
#endif

		n = m_copy(m, 0, M_COPYALL);
		if (n)
			n = ni6_input(n, off);
		if (n) {
			noff = sizeof(struct ip6_hdr);
			icmp6stat.icp6s_reflect++;
			icmp6stat.icp6s_outhist[ICMP6_WRUREPLY]++;
			icmp6_reflect(n, noff);
		}
		goto rate_limit_checked;

	case ICMP6_WRUREPLY:
		if (code != 0)
			goto badcode;
		break;

	case ND_ROUTER_SOLICIT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_routersolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_solicit))
			goto badlen;

		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_rs_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_rs_input(n, off, icmp6len);
		/* m stays. */
		goto rate_limit_checked;

	case ND_ROUTER_ADVERT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_routeradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_advert))
			goto badlen;

		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_ra_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ra_input(n, off, icmp6len);
		/* m stays. */
		goto rate_limit_checked;

	case ND_NEIGHBOR_SOLICIT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_neighborsolicit);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_solicit))
			goto badlen;

		if (proxy ||
		    ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL)) {
			/* give up local */
			nd6_ns_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ns_input(n, off, icmp6len);
		/* m stays. */
		goto rate_limit_checked;

	case ND_NEIGHBOR_ADVERT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_neighboradvert);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_advert))
			goto badlen;

		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			nd6_na_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_na_input(n, off, icmp6len);
		/* m stays. */
		goto rate_limit_checked;

	case ND_REDIRECT:
		icmp6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_redirect);
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_redirect))
			goto badlen;

		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			/* give up local */
			icmp6_redirect_input(m, off);
			m = NULL;
			goto freeit;
		}
		icmp6_redirect_input(n, off);
		/* m stays. */
		goto rate_limit_checked;

	case ICMP6_ROUTER_RENUMBERING:
		if (code != ICMP6_ROUTER_RENUMBERING_COMMAND &&
		    code != ICMP6_ROUTER_RENUMBERING_RESULT)
			goto badcode;
		if (icmp6len < sizeof(struct icmp6_router_renum))
			goto badlen;
		break;

	default:
		nd6log((LOG_DEBUG,
		    "icmp6_input: unknown type %d(src=%s, dst=%s, ifid=%d)\n",
		    icmp6->icmp6_type, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst),
		    m->m_pkthdr.rcvif ? m->m_pkthdr.rcvif->if_index : 0));
		if (icmp6->icmp6_type < ICMP6_ECHO_REQUEST) {
			/* ICMPv6 error: MUST deliver it by spec... */
			code = PRC_NCMDS;
			/* deliver */
		} else {
			/* ICMPv6 informational: MUST not deliver */
			goto rate_limit_checked;
		}
	deliver:
		if (icmp6_notify_error(m, off, icmp6len, code)) {
			/* In this case, m should've been freed. */
			return(IPPROTO_DONE);
		}
		break;

	badcode:
		icmp6stat.icp6s_badcode++;
		break;

	badlen:
		icmp6stat.icp6s_badlen++;
		break;
	}

rate_limit_checked:
	icmp6_rip6_input(&m, *offp);
	return IPPROTO_DONE;

freeit:
	m_freem(m);
	return IPPROTO_DONE;
}

static int
icmp6_notify_error(struct mbuf *m, int off, int icmp6len, int code)
{
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *eip6;
	u_int32_t notifymtu;
	struct sockaddr_in6 icmp6src, icmp6dst;

	if (icmp6len < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		goto freeit;
	}
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off,
			 sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr),
			 return -1);
	icmp6 = (struct icmp6_hdr *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off,
		       sizeof(*icmp6) + sizeof(struct ip6_hdr));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		return(-1);
	}
#endif
	eip6 = (struct ip6_hdr *)(icmp6 + 1);

	/* Detect the upper level protocol */
	{
		void (*ctlfunc)(int, struct sockaddr *, void *, struct ifnet *);
		u_int8_t nxt = eip6->ip6_nxt;
		int eoff = off + sizeof(struct icmp6_hdr) +
			sizeof(struct ip6_hdr);
		struct ip6ctlparam ip6cp;
		struct in6_addr *finaldst = NULL;
		int icmp6type = icmp6->icmp6_type;
		struct ip6_frag *fh;
		struct ip6_rthdr *rth;
		struct ip6_rthdr0 *rth0;
		int rthlen;

		while (1) { /* XXX: should avoid infinite loop explicitly? */
			struct ip6_ext *eh;

			switch (nxt) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_AH:
#ifndef PULLDOWN_TEST
				IP6_EXTHDR_CHECK(m, 0, eoff +
						 sizeof(struct ip6_ext),
						 return -1);
				eh = (struct ip6_ext *)(mtod(m, caddr_t)
							+ eoff);
#else
				IP6_EXTHDR_GET(eh, struct ip6_ext *, m,
					       eoff, sizeof(*eh));
				if (eh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return(-1);
				}
#endif

				if (nxt == IPPROTO_AH)
					eoff += (eh->ip6e_len + 2) << 2;
				else
					eoff += (eh->ip6e_len + 1) << 3;
				nxt = eh->ip6e_nxt;
				break;
			case IPPROTO_ROUTING:
				/*
				 * When the erroneous packet contains a
				 * routing header, we should examine the
				 * header to determine the final destination.
				 * Otherwise, we can't properly update
				 * information that depends on the final
				 * destination (e.g. path MTU).
				 */
#ifndef PULLDOWN_TEST
				IP6_EXTHDR_CHECK(m, 0, eoff + sizeof(*rth),
						 return -1);
				rth = (struct ip6_rthdr *)(mtod(m, caddr_t)
							   + eoff);
#else
				IP6_EXTHDR_GET(rth, struct ip6_rthdr *, m,
					       eoff, sizeof(*rth));
				if (rth == NULL) {
					icmp6stat.icp6s_tooshort++;
					return(-1);
				}
#endif
				rthlen = (rth->ip6r_len + 1) << 3;
				/*
				 * XXX: currently there is no
				 * officially defined type other
				 * than type-0.
				 * Note that if the segment left field
				 * is 0, all intermediate hops must
				 * have been passed.
				 */
				if (rth->ip6r_segleft &&
				    rth->ip6r_type == IPV6_RTHDR_TYPE_0) {
					int hops;

#ifndef PULLDOWN_TEST
					IP6_EXTHDR_CHECK(m, 0, eoff + rthlen,
							 return -1);
					rth0 = (struct ip6_rthdr0 *)(mtod(m, caddr_t) + eoff);
#else
					IP6_EXTHDR_GET(rth0,
						       struct ip6_rthdr0 *, m,
						       eoff, rthlen);
					if (rth0 == NULL) {
						icmp6stat.icp6s_tooshort++;
						return(-1);
					}
#endif
					/* just ignore a bogus header */
					if ((rth0->ip6r0_len % 2) == 0 &&
					    (hops = rth0->ip6r0_len/2))
						finaldst = (struct in6_addr *)(void *)(rth0 + 1) + (hops - 1);
				}
				eoff += rthlen;
				nxt = rth->ip6r_nxt;
				break;
			case IPPROTO_FRAGMENT:
#ifndef PULLDOWN_TEST
				IP6_EXTHDR_CHECK(m, 0, eoff +
						 sizeof(struct ip6_frag),
						 return -1);
				fh = (struct ip6_frag *)(mtod(m, caddr_t)
							 + eoff);
#else
				IP6_EXTHDR_GET(fh, struct ip6_frag *, m,
					       eoff, sizeof(*fh));
				if (fh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}
#endif
				/*
				 * Data after a fragment header is meaningless
				 * unless it is the first fragment, but
				 * we'll go to the notify label for path MTU
				 * discovery.
				 */
				if (fh->ip6f_offlg & IP6F_OFF_MASK)
					goto notify;

				eoff += sizeof(struct ip6_frag);
				nxt = fh->ip6f_nxt;
				break;
			default:
				/*
				 * This case includes ESP and the No Next
				 * Header.  In such cases going to the notify
				 * label does not have any meaning
				 * (i.e. ctlfunc will be NULL), but we go
				 * anyway since we might have to update
				 * path MTU information.
				 */
				goto notify;
			}
		}
	  notify:
#ifndef PULLDOWN_TEST
		icmp6 = (struct icmp6_hdr *)(mtod(m, caddr_t) + off);
#else
		IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off,
		    sizeof(*icmp6) + sizeof(struct ip6_hdr));
		if (icmp6 == NULL) {
			icmp6stat.icp6s_tooshort++;
			return (-1);
		}
#endif

		/*
		 * retrieve parameters from the inner IPv6 header, and convert
		 * them into sockaddr structures.
		 * XXX: there is no guarantee that the source or destination
		 * addresses of the inner packet are in the same scope as
		 * the addresses of the icmp packet.  But there is no other
		 * way to determine the zone.
		 */
		eip6 = (struct ip6_hdr *)(icmp6 + 1);

		bzero(&icmp6dst, sizeof(icmp6dst));
		icmp6dst.sin6_len = sizeof(struct sockaddr_in6);
		icmp6dst.sin6_family = AF_INET6;
		if (finaldst == NULL)
			icmp6dst.sin6_addr = eip6->ip6_dst;
		else
			icmp6dst.sin6_addr = *finaldst;
		if (in6_setscope(&icmp6dst.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
		bzero(&icmp6src, sizeof(icmp6src));
		icmp6src.sin6_len = sizeof(struct sockaddr_in6);
		icmp6src.sin6_family = AF_INET6;
		icmp6src.sin6_addr = eip6->ip6_src;
		if (in6_setscope(&icmp6src.sin6_addr, m->m_pkthdr.rcvif, NULL))
			goto freeit;
		icmp6src.sin6_flowinfo =
		    (eip6->ip6_flow & IPV6_FLOWLABEL_MASK);

		if (finaldst == NULL)
			finaldst = &eip6->ip6_dst;
		ip6cp.ip6c_m = m;
		ip6cp.ip6c_icmp6 = icmp6;
		ip6cp.ip6c_ip6 = (struct ip6_hdr *)(icmp6 + 1);
		ip6cp.ip6c_off = eoff;
		ip6cp.ip6c_finaldst = finaldst;
		ip6cp.ip6c_src = &icmp6src;
		ip6cp.ip6c_nxt = nxt;

		if (icmp6type == ICMP6_PACKET_TOO_BIG) {
			notifymtu = ntohl(icmp6->icmp6_mtu);
			ip6cp.ip6c_cmdarg = (void *)&notifymtu;
			icmp6_mtudisc_update(&ip6cp, 1);	/*XXX*/
		}

		ctlfunc = ip6_protox[nxt]->pr_ctlinput;
		if (ctlfunc) {
			LCK_MTX_ASSERT(inet6_domain_mutex, LCK_MTX_ASSERT_OWNED);

			lck_mtx_unlock(inet6_domain_mutex);

			(void) (*ctlfunc)(code, (struct sockaddr *)&icmp6dst,
			    &ip6cp, m->m_pkthdr.rcvif);

			lck_mtx_lock(inet6_domain_mutex);
		}
	}
	return(0);

freeit:
	m_freem(m);
	return(-1);
}

void
icmp6_mtudisc_update(struct ip6ctlparam *ip6cp, int validated)
{
	struct in6_addr *dst = ip6cp->ip6c_finaldst;
	struct icmp6_hdr *icmp6 = ip6cp->ip6c_icmp6;
	struct mbuf *m = ip6cp->ip6c_m;	/* will be necessary for scope issue */
	u_int mtu = ntohl(icmp6->icmp6_mtu);
	struct rtentry *rt = NULL;
	struct sockaddr_in6 sin6;
	/*
	 * we reject ICMPv6 too big with abnormally small value.
	 * XXX what is the good definition of "abnormally small"?
	 */
	if (mtu < sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + 8)
		return;

	if (!validated)
		return;

	/*
	 * In case the suggested mtu is less than IPV6_MMTU, we
	 * only need to remember that it was for above mentioned
	 * "alwaysfrag" case.
	 * Try to be as close to the spec as possible.
	 */
	if (mtu < IPV6_MMTU)
		mtu = IPV6_MMTU - 8;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = PF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_addr = *dst;
	/* XXX normally, this won't happen */
	if (IN6_IS_ADDR_LINKLOCAL(dst)) {
		sin6.sin6_addr.s6_addr16[1] =
		    htons(m->m_pkthdr.rcvif->if_index);
	}
	/* sin6.sin6_scope_id = XXX: should be set if DST is a scoped addr */
	/*
	 * XXX On a side note, for asymmetric data-path
	 * the lookup on receive interace is probably not
	 * what we want to do.
	 * That requires looking at the cached route for the
	 * protocol control block.
	 */
	rt = rtalloc1_scoped((struct sockaddr *)&sin6, 0,
	    RTF_CLONING | RTF_PRCLONING, m->m_pkthdr.rcvif->if_index);
	if (rt != NULL) {
		RT_LOCK(rt);
		if ((rt->rt_flags & RTF_HOST) &&
		    !(rt->rt_rmx.rmx_locks & RTV_MTU) &&
		    mtu < IN6_LINKMTU(rt->rt_ifp) &&
		    rt->rt_rmx.rmx_mtu > mtu) {
			icmp6stat.icp6s_pmtuchg++;
			rt->rt_rmx.rmx_mtu = mtu;
		}
		RT_UNLOCK(rt);
		rtfree(rt);
	}
}

/*
 * Process a Node Information Query packet, based on
 * draft-ietf-ipngwg-icmp-name-lookups-07.
 *
 * Spec incompatibilities:
 * - IPv6 Subject address handling
 * - IPv4 Subject address handling support missing
 * - Proxy reply (answer even if it's not for me)
 * - joins NI group address at in6_ifattach() time only, does not cope
 *   with hostname changes by sethostname(3)
 */
#define hostnamelen	strlen(hostname)
static struct mbuf *
ni6_input(struct mbuf *m, int off)
{
	struct icmp6_nodeinfo *ni6, *nni6;
	struct mbuf *n = NULL;
	u_int16_t qtype;
	int subjlen;
	int replylen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
	struct ni_reply_fqdn *fqdn;
	int addrs;		/* for NI_QTYPE_NODEADDR */
	struct ifnet *ifp = NULL; /* for NI_QTYPE_NODEADDR */
	struct sockaddr_in6 sin6; /* double meaning; ip6_dst and subjectaddr */
	struct sockaddr_in6 sin6_d; /* XXX: we should retrieve this from m_aux */
	struct ip6_hdr *ip6;
	int oldfqdn = 0;	/* if 1, return pascal string (03 draft) */
	char *subj = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
	ni6 = (struct icmp6_nodeinfo *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(ni6, struct icmp6_nodeinfo *, m, off, sizeof(*ni6));
	if (ni6 == NULL) {
		/* m is already reclaimed */
		return (NULL);
	}
#endif

	/*
	 * Validate IPv6 source address.
	 * The default configuration MUST be to refuse answering queries from
	 * global-scope addresses according to RFC4602.
	 * Notes:
	 *  - it's not very clear what "refuse" means; this implementation
	 *    simply drops it.
	 *  - it's not very easy to identify global-scope (unicast) addresses
	 *    since there are many prefixes for them.  It should be safer
	 *    and in practice sufficient to check "all" but loopback and
	 *    link-local (note that site-local unicast was deprecated and
	 *    ULA is defined as global scope-wise)
	 */
	if ((icmp6_nodeinfo & ICMP6_NODEINFO_GLOBALOK) == 0 &&
	    !IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) &&
	    !IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))
		goto bad;

	/*
	 * Validate IPv6 destination address.
	 *
	 * The Responder must discard the Query without further processing
	 * unless it is one of the Responder's unicast or anycast addresses, or
	 * a link-local scope multicast address which the Responder has joined.
	 * [RFC4602, Section 5.]
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (!IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst))
			goto bad;
		/* else it's a link-local multicast, fine */
	} else {		/* unicast or anycast */
		uint32_t ia6_flags;

		if (ip6_getdstifaddr_info(m, NULL, &ia6_flags) != 0)
			goto bad; /* XXX impossible */

		if ((ia6_flags & IN6_IFF_TEMPORARY) &&
		    !(icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK)) {
			nd6log((LOG_DEBUG, "ni6_input: ignore node info to "
				"a temporary address in %s:%d",
			       __func__, __LINE__));
			goto bad;
		}
	}

	/* validate query Subject field. */
	qtype = ntohs(ni6->ni_qtype);
	subjlen = m->m_pkthdr.len - off - sizeof(struct icmp6_nodeinfo);
	switch (qtype) {
	case NI_QTYPE_NOOP:
	case NI_QTYPE_SUPTYPES:
		/* 07 draft */
		if (ni6->ni_code == ICMP6_NI_SUBJ_FQDN && subjlen == 0)
			break;
		/* FALLTHROUGH */
	case NI_QTYPE_FQDN:
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
#if ICMP6_NI_SUBJ_IPV6 != 0
		case 0:
#endif
			/*
			 * backward compatibility - try to accept 03 draft
			 * format, where no Subject is present.
			 */
			if (qtype == NI_QTYPE_FQDN && ni6->ni_code == 0 &&
			    subjlen == 0) {
				oldfqdn++;
				break;
			}
#if ICMP6_NI_SUBJ_IPV6 != 0
			if (ni6->ni_code != ICMP6_NI_SUBJ_IPV6)
				goto bad;
#endif

			if (subjlen != sizeof(struct in6_addr))
				goto bad;

			/*
			 * Validate Subject address.
			 *
			 * Not sure what exactly "address belongs to the node"
			 * means in the spec, is it just unicast, or what?
			 *
			 * At this moment we consider Subject address as
			 * "belong to the node" if the Subject address equals
			 * to the IPv6 destination address; validation for
			 * IPv6 destination address should have done enough
			 * check for us.
			 *
			 * We do not do proxy at this moment.
			 */
			/* m_pulldown instead of copy? */
			m_copydata(m, off + sizeof(struct icmp6_nodeinfo),
			    subjlen, (caddr_t)&sin6.sin6_addr);
			sin6.sin6_scope_id = in6_addr2scopeid(m->m_pkthdr.rcvif,
							      &sin6.sin6_addr);
			in6_embedscope(&sin6.sin6_addr, &sin6, NULL, NULL,
			    NULL);
			bzero(&sin6_d, sizeof(sin6_d));
			sin6_d.sin6_family = AF_INET6; /* not used, actually */
			sin6_d.sin6_len = sizeof(sin6_d); /* ditto */
			sin6_d.sin6_addr = ip6->ip6_dst;
			sin6_d.sin6_scope_id = in6_addr2scopeid(m->m_pkthdr.rcvif,
								&ip6->ip6_dst);
			in6_embedscope(&sin6_d.sin6_addr, &sin6_d, NULL, NULL,
			    NULL);
			subj = (char *)&sin6;
			if (SA6_ARE_ADDR_EQUAL(&sin6, &sin6_d))
				break;

			/*
			 * XXX if we are to allow other cases, we should really
			 * be careful about scope here.
			 * basically, we should disallow queries toward IPv6
			 * destination X with subject Y,
			 * if scope(X) > scope(Y).
			 * if we allow scope(X) > scope(Y), it will result in
			 * information leakage across scope boundary.
			 */
			goto bad;

		case ICMP6_NI_SUBJ_FQDN:
			/*
			 * Validate Subject name with gethostname(3).
			 *
			 * The behavior may need some debate, since:
			 * - we are not sure if the node has FQDN as
			 *   hostname (returned by gethostname(3)).
			 * - the code does wildcard match for truncated names.
			 *   however, we are not sure if we want to perform
			 *   wildcard match, if gethostname(3) side has
			 *   truncated hostname.
			 */
			n = ni6_nametodns(hostname, hostnamelen, 0);
			if (!n || n->m_next || n->m_len == 0)
				goto bad;
			IP6_EXTHDR_GET(subj, char *, m,
			    off + sizeof(struct icmp6_nodeinfo), subjlen);
			if (subj == NULL)
				goto bad;
			if (!ni6_dnsmatch(subj, subjlen, mtod(n, const char *),
					n->m_len)) {
				goto bad;
			}
			m_freem(n);
			n = NULL;
			break;

		case ICMP6_NI_SUBJ_IPV4:	/* XXX: to be implemented? */
		default:
			goto bad;
		}
		break;
	}

	/* refuse based on configuration.  XXX ICMP6_NI_REFUSED? */
	switch (qtype) {
	case NI_QTYPE_FQDN:
		if ((icmp6_nodeinfo & ICMP6_NODEINFO_FQDNOK) == 0)
			goto bad;
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		if ((icmp6_nodeinfo & ICMP6_NODEINFO_NODEADDROK) == 0)
			goto bad;
		break;
	}

	/* guess reply length */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		break;		/* no reply data */
	case NI_QTYPE_SUPTYPES:
		replylen += sizeof(u_int32_t);
		break;
	case NI_QTYPE_FQDN:
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		break;
	case NI_QTYPE_NODEADDR:
		addrs = ni6_addrs(ni6, &ifp, subj);
		if ((replylen += addrs * (sizeof(struct in6_addr) +
		    sizeof(u_int32_t))) > MCLBYTES)
			replylen = MCLBYTES; /* XXX: will truncate pkt later */
		break;
	case NI_QTYPE_IPV4ADDR:
		/* unsupported - should respond with unknown Qtype? */
		break;
	default:
		/*
		 * XXX: We must return a reply with the ICMP6 code
		 * `unknown Qtype' in this case.  However we regard the case
		 * as an FQDN query for backward compatibility.
		 * Older versions set a random value to this field,
		 * so it rarely varies in the defined qtypes.
		 * But the mechanism is not reliable...
		 * maybe we should obsolete older versions.
		 */
		qtype = NI_QTYPE_FQDN;
		/* XXX will append an mbuf */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		oldfqdn++;
		break;
	}

	/* allocate an mbuf to reply. */
	MGETHDR(n, M_DONTWAIT, m->m_type);	/* MAC-OK */
	if (n == NULL) {
		m_freem(m);
		if (ifp != NULL)
			ifnet_release(ifp);
		return (NULL);
	}
	M_COPY_PKTHDR(n, m); /* just for recvif */
	if (replylen > MHLEN) {
		if (replylen > MCLBYTES) {
			/*
			 * XXX: should we try to allocate more? But MCLBYTES
			 * is probably much larger than IPV6_MMTU...
			 */
			goto bad;
		}
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			goto bad;
		}
	}
	n->m_pkthdr.len = n->m_len = replylen;

	/* copy mbuf header and IPv6 + Node Information base headers */
	bcopy(mtod(m, caddr_t), mtod(n, caddr_t), sizeof(struct ip6_hdr));
	nni6 = (struct icmp6_nodeinfo *)(mtod(n, struct ip6_hdr *) + 1);
	bcopy((caddr_t)ni6, (caddr_t)nni6, sizeof(struct icmp6_nodeinfo));

	/* qtype dependent procedure */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = 0;
		break;
	case NI_QTYPE_SUPTYPES:
	{
		u_int32_t v;
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = htons(0x0000);	/* raw bitmap */
		/* supports NOOP, SUPTYPES, FQDN, and NODEADDR */
		v = (u_int32_t)htonl(0x0000000f);
		bcopy(&v, nni6 + 1, sizeof(u_int32_t));
		break;
	}
	case NI_QTYPE_FQDN:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		fqdn = (struct ni_reply_fqdn *)(mtod(n, caddr_t) +
						sizeof(struct ip6_hdr) +
						sizeof(struct icmp6_nodeinfo));
		nni6->ni_flags = 0; /* XXX: meaningless TTL */
		fqdn->ni_fqdn_ttl = 0;	/* ditto. */
		/*
		 * XXX do we really have FQDN in variable "hostname"?
		 */
		n->m_next = ni6_nametodns(hostname, hostnamelen, oldfqdn);
		if (n->m_next == NULL)
			goto bad;
		/* XXX we assume that n->m_next is not a chain */
		if (n->m_next->m_next != NULL)
			goto bad;
		n->m_pkthdr.len += n->m_next->m_len;
		break;
	case NI_QTYPE_NODEADDR:
	{
		int lenlim, copied;

		nni6->ni_code = ICMP6_NI_SUCCESS;
		n->m_pkthdr.len = n->m_len =
		    sizeof(struct ip6_hdr) + sizeof(struct icmp6_nodeinfo);
		lenlim = M_TRAILINGSPACE(n);
		copied = ni6_store_addrs(ni6, nni6, ifp, lenlim);
		/* XXX: reset mbuf length */
		n->m_pkthdr.len = n->m_len = sizeof(struct ip6_hdr) +
			sizeof(struct icmp6_nodeinfo) + copied;
		break;
	}
	default:
		break;		/* XXX impossible! */
	}

	nni6->ni_type = ICMP6_NI_REPLY;
	m_freem(m);
	if (ifp != NULL)
		ifnet_release(ifp);
	return (n);

bad:
	m_freem(m);
	if (n)
		m_freem(n);
	if (ifp != NULL)
		ifnet_release(ifp);
	return (NULL);
}
#undef hostnamelen

/*
 * make a mbuf with DNS-encoded string.  no compression support.
 *
 * XXX names with less than 2 dots (like "foo" or "foo.section") will be
 * treated as truncated name (two \0 at the end).  this is a wild guess.
 */
static struct mbuf *
ni6_nametodns(
	const char *name,
	int namelen,
	int old)	/* return pascal string if non-zero */
{
	struct mbuf *m;
	char *cp, *ep;
	const char *p, *q;
	int i, len, nterm;

	if (old)
		len = namelen + 1;
	else
		len = MCLBYTES;

	/* because MAXHOSTNAMELEN is usually 256, we use cluster mbuf */
	MGET(m, M_DONTWAIT, MT_DATA);
	if (m && len > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0)
			goto fail;
	}
	if (!m)
		goto fail;
	m->m_next = NULL;

	if (old) {
		m->m_len = len;
		*mtod(m, char *) = namelen;
		bcopy(name, mtod(m, char *) + 1, namelen);
		return m;
	} else {
		m->m_len = 0;
		cp = mtod(m, char *);
		ep = mtod(m, char *) + M_TRAILINGSPACE(m);

		/* if not certain about my name, return empty buffer */
		if (namelen == 0)
			return m;

		/*
		 * guess if it looks like shortened hostname, or FQDN.
		 * shortened hostname needs two trailing "\0".
		 */
		i = 0;
		for (p = name; p < name + namelen; p++) {
			if (*p && *p == '.')
				i++;
		}
		if (i < 2)
			nterm = 2;
		else
			nterm = 1;

		p = name;
		while (cp < ep && p < name + namelen) {
			i = 0;
			for (q = p; q < name + namelen && *q && *q != '.'; q++)
				i++;
			/* result does not fit into mbuf */
			if (cp + i + 1 >= ep)
				goto fail;
			/*
			 * DNS label length restriction, RFC1035 page 8.
			 * "i == 0" case is included here to avoid returning
			 * 0-length label on "foo..bar".
			 */
			if (i <= 0 || i >= 64)
				goto fail;
			*cp++ = i;
			bcopy(p, cp, i);
			cp += i;
			p = q;
			if (p < name + namelen && *p == '.')
				p++;
		}
		/* termination */
		if (cp + nterm >= ep)
			goto fail;
		while (nterm-- > 0)
			*cp++ = '\0';
		m->m_len = cp - mtod(m, char *);
		return m;
	}

	panic("should not reach here");
	/* NOTREACHED */

 fail:
	if (m)
		m_freem(m);
	return NULL;
}

/*
 * check if two DNS-encoded string matches.  takes care of truncated
 * form (with \0\0 at the end).  no compression support.
 * XXX upper/lowercase match (see RFC2065)
 */
static int
ni6_dnsmatch(const char *a, int alen, const char *b, int blen)
{
	const char *a0, *b0;
	int l;

	/* simplest case - need validation? */
	if (alen == blen && bcmp(a, b, alen) == 0)
		return 1;

	a0 = a;
	b0 = b;

	/* termination is mandatory */
	if (alen < 2 || blen < 2)
		return 0;
	if (a0[alen - 1] != '\0' || b0[blen - 1] != '\0')
		return 0;
	alen--;
	blen--;

	while (a - a0 < alen && b - b0 < blen) {
		if (a - a0 + 1 > alen || b - b0 + 1 > blen)
			return 0;

		if ((signed char)a[0] < 0 || (signed char)b[0] < 0)
			return 0;
		/* we don't support compression yet */
		if (a[0] >= 64 || b[0] >= 64)
			return 0;

		/* truncated case */
		if (a[0] == 0 && a - a0 == alen - 1)
			return 1;
		if (b[0] == 0 && b - b0 == blen - 1)
			return 1;
		if (a[0] == 0 || b[0] == 0)
			return 0;

		if (a[0] != b[0])
			return 0;
		l = a[0];
		if (a - a0 + 1 + l > alen || b - b0 + 1 + l > blen)
			return 0;
		if (bcmp(a + 1, b + 1, l) != 0)
			return 0;

		a += 1 + l;
		b += 1 + l;
	}

	if (a - a0 == alen && b - b0 == blen)
		return 1;
	else
		return 0;
}

/*
 * calculate the number of addresses to be returned in the node info reply.
 */
static int
ni6_addrs(struct icmp6_nodeinfo *ni6, struct ifnet **ifpp, char *subj)
{
	struct ifnet *ifp;
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	struct sockaddr_in6 *subj_ip6 = NULL; /* XXX pedant */
	int addrs = 0, addrsofif, iffound = 0;
	int niflags = ni6->ni_flags;

	if (ifpp != NULL)
		*ifpp = NULL;

	if ((niflags & NI_NODEADDR_FLAG_ALL) == 0) {
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
			if (subj == NULL) /* must be impossible... */
				return(0);
			subj_ip6 = (struct sockaddr_in6 *)(void *)subj;
			break;
		default:
			/*
			 * XXX: we only support IPv6 subject address for
			 * this Qtype.
			 */
			return (0);
		}
	}

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		addrsofif = 0;
		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
		{
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ifa);
				continue;
			}
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((niflags & NI_NODEADDR_FLAG_ALL) == 0 &&
			    IN6_ARE_ADDR_EQUAL(&subj_ip6->sin6_addr,
					       &ifa6->ia_addr.sin6_addr))
				iffound = 1;

			/*
			 * IPv4-mapped addresses can only be returned by a
			 * Node Information proxy, since they represent
			 * addresses of IPv4-only nodes, which perforce do
			 * not implement this protocol.
			 * [icmp-name-lookups-07, Section 5.4]
			 * So we don't support NI_NODEADDR_FLAG_COMPAT in
			 * this function at this moment.
			 */

			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			default:
				IFA_UNLOCK(ifa);
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0) {
				IFA_UNLOCK(ifa);
				continue; /* we need only unicast addresses */
			}
			if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
			    (icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK) == 0) {
				IFA_UNLOCK(ifa);
				continue;
			}
			addrsofif++; /* count the address */
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
		if (iffound) {
			if (ifpp != NULL) {
				*ifpp = ifp;
				ifnet_reference(ifp);
			}
			ifnet_head_done();
			return(addrsofif);
		}

		addrs += addrsofif;
	}
	ifnet_head_done();

	return (addrs);
}

static int
ni6_store_addrs(struct icmp6_nodeinfo *ni6, struct icmp6_nodeinfo *nni6,
		struct ifnet *ifp0, int resid)
{
	struct ifnet *ifp = ifp0;
	struct in6_ifaddr *ifa6;
	struct ifaddr *ifa;
	struct ifnet *ifp_dep = NULL;
	int copied = 0, allow_deprecated = 0;
	u_char *cp = (u_char *)(nni6 + 1);
	int niflags = ni6->ni_flags;
	u_int32_t ltime;
	uint64_t now = net_uptime();

	if (ifp0 == NULL && !(niflags & NI_NODEADDR_FLAG_ALL))
		return (0);	/* needless to copy */

  again:

	ifnet_head_lock_shared();
	if (ifp == NULL)
		ifp = TAILQ_FIRST(&ifnet_head);

	for (; ifp; ifp = TAILQ_NEXT(ifp, if_list)) {
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next) {
			struct in6_addrlifetime_i *lt;

			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ifa);
				continue;
			}
			ifa6 = (struct in6_ifaddr *)ifa;

			if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) != 0 &&
			    allow_deprecated == 0) {
				/*
				 * prefererred address should be put before
				 * deprecated addresses.
				 */

				/* record the interface for later search */
				if (ifp_dep == NULL)
					ifp_dep = ifp;

				IFA_UNLOCK(ifa);
				continue;
			} else if ((ifa6->ia6_flags & IN6_IFF_DEPRECATED) == 0 &&
			    allow_deprecated != 0) {
				IFA_UNLOCK(ifa);
				continue; /* we now collect deprecated addrs */
			}
			/* What do we have to do about ::1? */
			switch (in6_addrscope(&ifa6->ia_addr.sin6_addr)) {
			case IPV6_ADDR_SCOPE_LINKLOCAL:
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			case IPV6_ADDR_SCOPE_SITELOCAL:
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			case IPV6_ADDR_SCOPE_GLOBAL:
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
				break;
			default:
				IFA_UNLOCK(ifa);
				continue;
			}

			/*
			 * check if anycast is okay.
			 * XXX: just experimental.  not in the spec.
			 */
			if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0) {
				IFA_UNLOCK(ifa);
				continue;
			}
			if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
			    (icmp6_nodeinfo & ICMP6_NODEINFO_TMPADDROK) == 0) {
				IFA_UNLOCK(ifa);
				continue;
			}

			/* now we can copy the address */
			if (resid < sizeof(struct in6_addr) +
			    sizeof(u_int32_t)) {
				IFA_UNLOCK(ifa);
				/*
				 * We give up much more copy.
				 * Set the truncate flag and return.
				 */
				nni6->ni_flags |=
					NI_NODEADDR_FLAG_TRUNCATE;
				ifnet_lock_done(ifp);
				ifnet_head_done();
				return(copied);
			}

			/*
			 * Set the TTL of the address.
			 * The TTL value should be one of the following
			 * according to the specification:
			 *
			 * 1. The remaining lifetime of a DHCP lease on the
			 *    address, or
			 * 2. The remaining Valid Lifetime of a prefix from
			 *    which the address was derived through Stateless
			 *    Autoconfiguration.
			 *
			 * Note that we currently do not support stateful
			 * address configuration by DHCPv6, so the former
			 * case can't happen.
			 */
			lt = &ifa6->ia6_lifetime;
			if (lt->ia6ti_expire == 0) {
				ltime = ND6_INFINITE_LIFETIME;
			} else {
				if (lt->ia6ti_expire > now)
					ltime = htonl(lt->ia6ti_expire - now);
				else
					ltime = 0;
			}

			bcopy(&ltime, cp, sizeof(u_int32_t));
			cp += sizeof(u_int32_t);

			/* copy the address itself */
			bcopy(&ifa6->ia_addr.sin6_addr, cp,
			      sizeof(struct in6_addr));
			/* XXX: KAME link-local hack; remove ifindex */
			if (IN6_IS_ADDR_LINKLOCAL(&ifa6->ia_addr.sin6_addr))
				((struct in6_addr *)(void *)cp)->s6_addr16[1] = 0;
			cp += sizeof(struct in6_addr);

			resid -= (sizeof(struct in6_addr) + sizeof(u_int32_t));
			copied += (sizeof(struct in6_addr) +
				   sizeof(u_int32_t));
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
		if (ifp0)	/* we need search only on the specified IF */
			break;
	}
	ifnet_head_done();

	if (allow_deprecated == 0 && ifp_dep != NULL) {
		ifp = ifp_dep;
		allow_deprecated = 1;

		goto again;
	}

	return(copied);
}

/*
 * XXX almost dup'ed code with rip6_input.
 */
static int
icmp6_rip6_input(struct mbuf **mp, int off)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct in6pcb *in6p;
	struct in6pcb *last = NULL;
	struct sockaddr_in6 rip6src;
	struct icmp6_hdr *icmp6;
	struct mbuf *opts = NULL;
	int ret = 0;
	struct ifnet *ifp = m->m_pkthdr.rcvif;

#ifndef PULLDOWN_TEST
	/* this is assumed to be safe. */
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		/* m is already reclaimed */
		return IPPROTO_DONE;
	}
#endif

	/*
	 * XXX: the address may have embedded scope zone ID, which should be
	 * hidden from applications.
	 */
	bzero(&rip6src, sizeof(rip6src));
	rip6src.sin6_family = AF_INET6;
	rip6src.sin6_len = sizeof(struct sockaddr_in6);
	rip6src.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&rip6src, TRUE))
		return (IPPROTO_DONE);

	lck_rw_lock_shared(ripcbinfo.ipi_lock);
	LIST_FOREACH(in6p, &ripcb, inp_list)
	{
		if ((in6p->inp_vflag & INP_IPV6) == 0)
			continue;
		if (in6p->in6p_ip6_nxt != IPPROTO_ICMPV6)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		   !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (in6p->in6p_icmp6filt
		    && ICMP6_FILTER_WILLBLOCK(icmp6->icmp6_type,
				 in6p->in6p_icmp6filt))
			continue;

		if (inp_restricted_recv(in6p, ifp))
			continue;

		if (last) {
			struct	mbuf *n;
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if ((last->in6p_flags & INP_CONTROLOPTS) != 0 ||
				    (last->in6p_socket->so_options & SO_TIMESTAMP) != 0 ||
				    (last->in6p_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
					ret = ip6_savecontrol(last, n, &opts);
					if (ret != 0) {
						m_freem(n);
						m_freem(opts);
						last = in6p;
						continue;
					}
				}
				/* strip intermediate headers */
				m_adj(n, off);
				so_recv_data_stat(last->in6p_socket, m, 0);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
						 (struct sockaddr *)&rip6src,
						 n, opts, NULL) != 0) {
					sorwakeup(last->in6p_socket);
				}
				opts = NULL;
			}
		}
		last = in6p;
	}
	if (last) {
		if ((last->in6p_flags & INP_CONTROLOPTS) != 0 ||
		    (last->in6p_socket->so_options & SO_TIMESTAMP) != 0 ||
		    (last->in6p_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
			ret = ip6_savecontrol(last, m, &opts);
			if (ret != 0) {
				goto error;
			}
		}
		/* strip intermediate headers */
		m_adj(m, off);
		so_recv_data_stat(last->in6p_socket, m, 0);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				 (struct sockaddr *)&rip6src, m, opts, NULL) != 0) {
			sorwakeup(last->in6p_socket);
		}
	} else {
		goto error;
	}
	lck_rw_done(ripcbinfo.ipi_lock);
	return IPPROTO_DONE;

error:
	lck_rw_done(ripcbinfo.ipi_lock);
	m_freem(m);
	m_freem(opts);
	ip6stat.ip6s_delivered--;
	return IPPROTO_DONE;
}

/*
 * Reflect the ip6 packet back to the source.
 * OFF points to the icmp6 header, counted from the top of the mbuf.
 */
void
icmp6_reflect(struct mbuf *m, size_t off)
{
	struct mbuf *m_ip6hdr = m;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct in6_ifaddr *ia;
	struct in6_addr t, src_storage, *src = 0;
	int plen;
	int type, code;
	struct ifnet *outif = NULL;
	struct sockaddr_in6 sa6_src, sa6_dst;
	struct nd_ifinfo *ndi = NULL;
	u_int32_t oflow;
	struct ip6_out_args ip6oa = { IFSCOPE_NONE, { 0 },
	    IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR |
	    IP6OAF_INTCOPROC_ALLOWED | IP6OAF_AWDL_UNRESTRICTED, 0,
	    SO_TC_UNSPEC, _NET_SERVICE_TYPE_UNSPEC };

	if (!(m->m_pkthdr.pkt_flags & PKTF_LOOP) && m->m_pkthdr.rcvif != NULL) {
		ip6oa.ip6oa_boundif = m->m_pkthdr.rcvif->if_index;
		ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
	}

	/* too short to reflect */
	if (off < sizeof(struct ip6_hdr)) {
		nd6log((LOG_DEBUG,
		    "sanity fail: off=%lx, sizeof(ip6)=%lx in %s:%d\n",
		    (u_int32_t)off, (u_int32_t)sizeof(struct ip6_hdr),
		    __func__, __LINE__));
		goto bad;
	}

	/*
	 * If there are extra headers between IPv6 and ICMPv6, strip
	 * off that header first.
	 */
	if (off > sizeof(struct ip6_hdr)) {
		size_t l;
		struct ip6_hdr nip6;

		l = off - sizeof(struct ip6_hdr);
		m_copydata(m, 0, sizeof(nip6), (caddr_t)&nip6);
		m_adj(m, l);
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m_ip6hdr = m_pulldown(m, 0, l, NULL)) == NULL)
				return;
		}
		bcopy((caddr_t)&nip6, mtod(m, caddr_t), sizeof(nip6));
	} else /* off == sizeof(struct ip6_hdr) */ {
		size_t l;
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m_ip6hdr = m_pulldown(m, 0, l, NULL)) == NULL)
				return;
		}
	}
	plen = m->m_pkthdr.len - sizeof(struct ip6_hdr);
	ip6 = mtod(m_ip6hdr, struct ip6_hdr *);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);
	type = icmp6->icmp6_type; /* keep type for statistics */
	code = icmp6->icmp6_code; /* ditto. */

	t = ip6->ip6_dst;
	/*
	 * ip6_input() drops a packet if its src is multicast.
	 * So, the src is never multicast.
	 */
	ip6->ip6_dst = ip6->ip6_src;

	/*
	 * XXX: make sure to embed scope zone information, using
	 * already embedded IDs or the received interface (if any).
	 * Note that rcvif may be NULL.
	 */
	bzero(&sa6_src, sizeof(sa6_src));
	sa6_src.sin6_family = AF_INET6;
	sa6_src.sin6_len = sizeof(sa6_src);
	sa6_src.sin6_addr = ip6->ip6_dst;
	in6_recoverscope(&sa6_src, &ip6->ip6_dst, m->m_pkthdr.rcvif);
	in6_embedscope(&ip6->ip6_dst, &sa6_src, NULL, NULL, NULL);
	bzero(&sa6_dst, sizeof(sa6_dst));
	sa6_dst.sin6_family = AF_INET6;
	sa6_dst.sin6_len = sizeof(sa6_dst);
	sa6_dst.sin6_addr = t;
	in6_recoverscope(&sa6_dst, &t, m->m_pkthdr.rcvif);
	in6_embedscope(&t, &sa6_dst, NULL, NULL, NULL);

	/*
	 * If the incoming packet was addressed directly to us(i.e. unicast),
	 * use dst as the src for the reply.
	 * The IN6_IFF_NOTREADY case should be VERY rare, but is possible
	 * (for example) when we encounter an error while forwarding procedure
	 * destined to a duplicated address of ours.
	 * Note that ip6_getdstifaddr() may fail if we are in an error handling
	 * procedure of an outgoing packet of our own, in which case we need
	 * to search in the ifaddr list.
	 */
	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		IFA_LOCK(&ia->ia_ifa);
		if (IN6_ARE_ADDR_EQUAL(&t, &ia->ia_addr.sin6_addr) &&
		    (ia->ia6_flags & (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY)) == 0) {
			IFA_UNLOCK(&ia->ia_ifa);
			src = &t;
			break;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);
	if (ia == NULL && IN6_IS_ADDR_LINKLOCAL(&t) &&
	    ((m->m_flags & M_LOOP) || (m->m_pkthdr.pkt_flags & PKTF_LOOP))) {
		/*
		 * This is the case if the dst is our link-local address
		 * and the sender is also ourselves.  Here we test for both
		 * M_LOOP and PKTF_LOOP, since the former may have been set
		 * in ip6_output() and that we get here as part of callling
		 * ip6_process_hopopts().  See comments in <sys/mbuf.h>
		 */
		src = &t;
	}

	if (src == NULL) {
		int e;
		struct sockaddr_in6 sin6;
		struct route_in6 ro;

		/*
		 * This case matches to multicasts, our anycast, or unicasts
		 * that we do not own.  Select a source address based on the
		 * source address of the erroneous packet.
		 */
		bzero(&sin6, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_addr = ip6->ip6_dst; /* zone ID should be embedded */

		bzero(&ro, sizeof(ro));
		/*
		 * in6_selectsrc() might return outif with its reference held
		 * even in the error case, so we always need to release it
		 * if non-NULL.
		 */
		src = in6_selectsrc(&sin6, NULL, NULL, &ro, &outif,
		    &src_storage, ip6oa.ip6oa_boundif, &e);
		ROUTE_RELEASE(&ro);
		if (src == NULL) {
			nd6log((LOG_DEBUG,
			    "icmp6_reflect: source can't be determined: "
			    "dst=%s, error=%d\n",
			    ip6_sprintf(&sa6_src.sin6_addr), e));
			goto bad;
		}
	}
	oflow = ip6->ip6_flow; /* Save for later */
	ip6->ip6_src = *src;
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY && icmp6->icmp6_code == 0) {
		ip6->ip6_flow |= (oflow & htonl(0x0ff00000));
	}
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	if (outif != NULL && (ndi = ND_IFINFO(outif)) != NULL &&
	    ndi->initialized) {
		lck_mtx_lock(&ndi->lock);
		ip6->ip6_hlim = ndi->chlim;
		lck_mtx_unlock(&ndi->lock);
	}
	if (m->m_pkthdr.rcvif != NULL &&
	    (ndi = ND_IFINFO(m->m_pkthdr.rcvif)) != NULL &&
	    ndi->initialized) {
		/* XXX: This may not be the outgoing interface */
		lck_mtx_lock(&ndi->lock);
		ip6->ip6_hlim = ndi->chlim;
		lck_mtx_unlock(&ndi->lock);
	} else {
		ip6->ip6_hlim = ip6_defhlim;
	}
	/* Use the same traffic class as in the request to match IPv4 */
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in6_cksum(m, IPPROTO_ICMPV6,
	    sizeof(struct ip6_hdr), plen);

	/*
	 * XXX option handling
	 */
	m->m_flags &= ~(M_BCAST|M_MCAST);

	if (outif != NULL) {
		ifnet_release(outif);
		outif = NULL;
	}

	m->m_pkthdr.csum_data = 0;
	m->m_pkthdr.csum_flags = 0;
	ip6_output(m, NULL, NULL, IPV6_OUTARGS, NULL, &outif, &ip6oa);
	if (outif != NULL) {
		icmp6_ifoutstat_inc(outif, type, code);
		ifnet_release(outif);
	}
	return;

bad:
	m_freem(m);
	if (outif != NULL)
		ifnet_release(outif);
	return;
}

static const char *
icmp6_redirect_diag(struct in6_addr *src6,
		    struct in6_addr *dst6,
		    struct in6_addr *tgt6)
{
	static char buf[1024];
	snprintf(buf, sizeof(buf), "(src=%s dst=%s tgt=%s)",
		ip6_sprintf(src6), ip6_sprintf(dst6), ip6_sprintf(tgt6));
	return buf;
}

void
icmp6_redirect_input(struct mbuf *m, int off)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_redirect *nd_rd;
	int icmp6len = ntohs(ip6->ip6_plen);
	char *lladdr = NULL;
	int lladdrlen = 0;
	u_char *redirhdr = NULL;
	int redirhdrlen = 0;
	struct rtentry *rt = NULL;
	int is_router;
	int is_onlink;
	struct in6_addr src6 = ip6->ip6_src;
	struct in6_addr redtgt6;
	struct in6_addr reddst6;
	union nd_opts ndopts;

	if (!m || !ifp)
		return;

	/*
	 * If we are an advertising router on this interface,
	 * don't update route by icmp6 redirect.
	 */
	if (ifp->if_eflags & IFEF_IPV6_ROUTER)
		goto freeit;
	if (!icmp6_rediraccept)
		goto freeit;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, return);
	nd_rd = (struct nd_redirect *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_rd, struct nd_redirect *, m, off, icmp6len);
	if (nd_rd == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif
	redtgt6 = nd_rd->nd_rd_target;
	reddst6 = nd_rd->nd_rd_dst;

	if (in6_setscope(&redtgt6, m->m_pkthdr.rcvif, NULL) ||
	    in6_setscope(&reddst6, m->m_pkthdr.rcvif, NULL)) {
		goto freeit;
	}

	/* validation */
	if (!IN6_IS_ADDR_LINKLOCAL(&src6)) {
		nd6log((LOG_ERR,
			"ICMP6 redirect sent from %s rejected; "
			"must be from linklocal\n", ip6_sprintf(&src6)));
		goto bad;
	}
	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
			"ICMP6 redirect sent from %s rejected; "
			"hlim=%d (must be 255)\n",
			ip6_sprintf(&src6), ip6->ip6_hlim));
		goto bad;
	}
    {
	/* ip6->ip6_src must be equal to gw for icmp6->icmp6_reddst */
	struct sockaddr_in6 sin6;
	struct in6_addr *gw6;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sin6.sin6_addr, sizeof(reddst6));
	rt = rtalloc1_scoped((struct sockaddr *)&sin6, 0, 0, ifp->if_index);
	if (rt) {
		RT_LOCK(rt);
		if (rt->rt_gateway == NULL ||
		    rt->rt_gateway->sa_family != AF_INET6) {
			nd6log((LOG_ERR,
			    "ICMP6 redirect rejected; no route "
			    "with inet6 gateway found for redirect dst: %s\n",
			    icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			RT_UNLOCK(rt);
			rtfree(rt);
			goto bad;
		}

		gw6 = &(((struct sockaddr_in6 *)(void *)
		    rt->rt_gateway)->sin6_addr);
		if (bcmp(&src6, gw6, sizeof(struct in6_addr)) != 0) {
			nd6log((LOG_ERR,
				"ICMP6 redirect rejected; "
				"not equal to gw-for-src=%s (must be same): "
				"%s\n",
				ip6_sprintf(gw6),
				icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
			RT_UNLOCK(rt);
			rtfree(rt);
			goto bad;
		}
	} else {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"no route found for redirect dst: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	RT_UNLOCK(rt);
	rtfree(rt);
	rt = NULL;
    }
	if (IN6_IS_ADDR_MULTICAST(&reddst6)) {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"redirect dst must be unicast: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	is_router = is_onlink = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&redtgt6))
		is_router = 1;	/* router case */
	if (bcmp(&redtgt6, &reddst6, sizeof(redtgt6)) == 0)
		is_onlink = 1;	/* on-link destination case */
	if (!is_router && !is_onlink) {
		nd6log((LOG_ERR,
			"ICMP6 redirect rejected; "
			"neither router case nor onlink case: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}
	/* validation passed */

	icmp6len -= sizeof(*nd_rd);
	nd6_option_init(nd_rd + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO, "icmp6_redirect_input: "
			"invalid ND option, rejected: %s\n",
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
	}

	if (ndopts.nd_opts_rh) {
		redirhdrlen = ndopts.nd_opts_rh->nd_opt_rh_len;
		redirhdr = (u_char *)(ndopts.nd_opts_rh + 1); /* xxx */
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
			"icmp6_redirect_input: lladdrlen mismatch for %s "
			"(if %d, icmp6 packet %d): %s\n",
			ip6_sprintf(&redtgt6), ifp->if_addrlen, lladdrlen - 2,
			icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));
		goto bad;
	}

	/* RFC 2461 8.3 */
	nd6_cache_lladdr(ifp, &redtgt6, lladdr, lladdrlen, ND_REDIRECT,
			 is_onlink ? ND_REDIRECT_ONLINK : ND_REDIRECT_ROUTER);

	if (!is_onlink) {	/* better router case.  perform rtredirect. */
		/* perform rtredirect */
		struct sockaddr_in6 sdst;
		struct sockaddr_in6 sgw;
		struct sockaddr_in6 ssrc;

		bzero(&sdst, sizeof(sdst));
		bzero(&sgw, sizeof(sgw));
		bzero(&ssrc, sizeof(ssrc));
		sdst.sin6_family = sgw.sin6_family = ssrc.sin6_family = AF_INET6;
		sdst.sin6_len = sgw.sin6_len = ssrc.sin6_len =
			sizeof(struct sockaddr_in6);
		bcopy(&redtgt6, &sgw.sin6_addr, sizeof(struct in6_addr));
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		bcopy(&src6, &ssrc.sin6_addr, sizeof(struct in6_addr));
		rtredirect(ifp, (struct sockaddr *)&sdst,
		    (struct sockaddr *)&sgw, NULL, RTF_GATEWAY | RTF_HOST,
		    (struct sockaddr *)&ssrc, NULL);
	}
	/* finally update cached route in each socket via pfctlinput */
    {
	struct sockaddr_in6 sdst;

	bzero(&sdst, sizeof(sdst));
	sdst.sin6_family = AF_INET6;
	sdst.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));

	pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&sdst);
#if IPSEC
	key_sa_routechange((struct sockaddr *)&sdst);
#endif
    }

 freeit:
	m_freem(m);
	return;

 bad:
	icmp6stat.icp6s_badredirect++;
	m_freem(m);
}

void
icmp6_redirect_output(struct mbuf *m0, struct rtentry *rt)
{
	struct ifnet *ifp;	/* my outgoing interface */
	struct in6_addr ifp_ll6;
	struct in6_addr *router_ll6;
	struct ip6_hdr *sip6;	/* m0 as struct ip6_hdr */
	struct mbuf *m = NULL;	/* newly allocated one */
	struct ip6_hdr *ip6;	/* m as struct ip6_hdr */
	struct nd_redirect *nd_rd;
	size_t maxlen;
	u_char *p;
	struct ifnet *outif = NULL;
	struct sockaddr_in6 src_sa;
	struct ip6_out_args ip6oa = { IFSCOPE_NONE, { 0 },
	    IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR, 0,
	    SO_TC_UNSPEC, _NET_SERVICE_TYPE_UNSPEC };

	icmp6_errcount(&icmp6stat.icp6s_outerrhist, ND_REDIRECT, 0);

	if (rt != NULL)
		RT_LOCK(rt);

	/* sanity check */
	if (!m0 || !rt || !(rt->rt_flags & RTF_UP) || !(ifp = rt->rt_ifp))
		goto fail;

	/*
	 * If we are not a router to begin with, or not an advertising
	 * router on this interface, don't send icmp6 redirect.
	 */
	if (!ip6_forwarding || !(ifp->if_eflags & IFEF_IPV6_ROUTER))
		goto fail;

	/*
	 * Address check:
	 *  the source address must identify a neighbor, and
	 *  the destination address must not be a multicast address
	 *  [RFC 2461, sec 8.2]
	 */
	sip6 = mtod(m0, struct ip6_hdr *);
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = sip6->ip6_src;
	/* we don't currently use sin6_scope_id, but eventually use it */
	src_sa.sin6_scope_id = in6_addr2scopeid(ifp, &sip6->ip6_src);
	RT_UNLOCK(rt);
	if (nd6_is_addr_neighbor(&src_sa, ifp, 0) == 0) {
		/* already unlocked */
		rt = NULL;
		goto fail;
	}
	RT_LOCK(rt);
	if (IN6_IS_ADDR_MULTICAST(&sip6->ip6_dst))
		goto fail;	/* what should we do here? */

	/* rate limit */
	if (icmp6_ratelimit(&sip6->ip6_src, ND_REDIRECT, 0))
		goto fail;

	/*
	 * Since we are going to append up to 1280 bytes (= IPV6_MMTU),
	 * we almost always ask for an mbuf cluster for simplicity.
	 * (MHLEN < IPV6_MMTU is almost always true)
	 */
#if IPV6_MMTU >= MCLBYTES
# error assumption failed about IPV6_MMTU and MCLBYTES
#endif
	MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
	if (m && IPV6_MMTU >= MHLEN)
		MCLGET(m, M_DONTWAIT);
	if (!m)
		goto fail;
	m->m_pkthdr.rcvif = NULL;
	m->m_len = 0;
	maxlen = M_TRAILINGSPACE(m);
	maxlen = min(IPV6_MMTU, maxlen);
	/* just for safety */
	if (maxlen < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
	    ((sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7)) {
		goto fail;
	}

	{
		/* get ip6 linklocal address for ifp(my outgoing interface). */
		struct in6_ifaddr *ia;
		if ((ia = in6ifa_ifpforlinklocal(ifp,
						 IN6_IFF_NOTREADY|
						 IN6_IFF_ANYCAST)) == NULL)
			goto fail;
		IFA_LOCK(&ia->ia_ifa);
		ifp_ll6 = ia->ia_addr.sin6_addr;
		IFA_UNLOCK(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);
	}

	/* get ip6 linklocal address for the router. */
	if (rt->rt_gateway && (rt->rt_flags & RTF_GATEWAY)) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)(void *)rt->rt_gateway;
		router_ll6 = &sin6->sin6_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(router_ll6))
			router_ll6 = (struct in6_addr *)NULL;
	} else
		router_ll6 = (struct in6_addr *)NULL;

	/* ip6 */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	/* ip6->ip6_src must be linklocal addr for my outgoing if. */
	bcopy(&ifp_ll6, &ip6->ip6_src, sizeof(struct in6_addr));
	bcopy(&sip6->ip6_src, &ip6->ip6_dst, sizeof(struct in6_addr));

	/* ND Redirect */
	nd_rd = (struct nd_redirect *)(ip6 + 1);
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	if (rt->rt_flags & RTF_GATEWAY) {
		/*
		 * nd_rd->nd_rd_target must be a link-local address in
		 * better router cases.
		 */
		if (!router_ll6)
			goto fail;
		bcopy(router_ll6, &nd_rd->nd_rd_target,
		      sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		      sizeof(nd_rd->nd_rd_dst));
	} else {
		/* make sure redtgt == reddst */
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_target,
		      sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst,
		      sizeof(nd_rd->nd_rd_dst));
	}
	RT_UNLOCK(rt);
	rt = NULL;

	p = (u_char *)(nd_rd + 1);

	if (!router_ll6)
		goto nolladdropt;

	{
		/* target lladdr option */
		struct rtentry *rt_router = NULL;
		int len;
		struct sockaddr_dl *sdl;
		struct nd_opt_hdr *nd_opt;
		char *lladdr;

		/* Callee returns a locked route upon success */
		rt_router = nd6_lookup(router_ll6, 0, ifp, 0);
		if (!rt_router)
			goto nolladdropt;
		RT_LOCK_ASSERT_HELD(rt_router);
		len = sizeof(*nd_opt) + ifp->if_addrlen;
		len = (len + 7) & ~7;	/* round by 8 */
		/* safety check */
		if (len + (p - (u_char *)ip6) > maxlen) {
			RT_REMREF_LOCKED(rt_router);
			RT_UNLOCK(rt_router);
			goto nolladdropt;
		}

		if (!(rt_router->rt_flags & RTF_GATEWAY) &&
			(rt_router->rt_flags & RTF_LLINFO) &&
			(rt_router->rt_gateway->sa_family == AF_LINK) &&
			(sdl = (struct sockaddr_dl *)(void *)
			rt_router->rt_gateway) && sdl->sdl_alen) {
				nd_opt = (struct nd_opt_hdr *)p;
				nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
				nd_opt->nd_opt_len = len >> 3;
				lladdr = (char *)(nd_opt + 1);
				bcopy(LLADDR(sdl), lladdr, ifp->if_addrlen);
				p += len;
		}
		RT_REMREF_LOCKED(rt_router);
		RT_UNLOCK(rt_router);
	}

nolladdropt:;

	m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

	/* just to be safe */
#ifdef M_DECRYPTED	/*not openbsd*/
	if (m0->m_flags & M_DECRYPTED)
		goto noredhdropt;
#endif
	if (p - (u_char *)ip6 > maxlen)
		goto noredhdropt;

    {
	/* redirected header option */
	int len;
	struct nd_opt_rd_hdr *nd_opt_rh;

	/*
	 * compute the maximum size for icmp6 redirect header option.
	 * XXX room for auth header?
	 */
	len = maxlen - (p - (u_char *)ip6);
	len &= ~7;

	/* This is just for simplicity. */
	if (m0->m_pkthdr.len != m0->m_len) {
		if (m0->m_next) {
			m_freem(m0->m_next);
			m0->m_next = NULL;
		}
		m0->m_pkthdr.len = m0->m_len;
	}

	/*
	 * Redirected header option spec (RFC2461 4.6.3) talks nothing
	 * about padding/truncate rule for the original IP packet.
	 * From the discussion on IPv6imp in Feb 1999, the consensus was:
	 * - "attach as much as possible" is the goal
	 * - pad if not aligned (original size can be guessed by original
	 *   ip6 header)
	 * Following code adds the padding if it is simple enough,
	 * and truncates if not.
	 */
	if (m0->m_next || m0->m_pkthdr.len != m0->m_len)
		panic("assumption failed in %s:%d\n", __func__, __LINE__);

	if (len - sizeof(*nd_opt_rh) < m0->m_pkthdr.len) {
		/* not enough room, truncate */
		m0->m_pkthdr.len = m0->m_len = len - sizeof(*nd_opt_rh);
	} else {
		/* enough room, pad or truncate */
		size_t extra;

		extra = m0->m_pkthdr.len % 8;
		if (extra) {
			/* pad if easy enough, truncate if not */
			if (8 - extra <= M_TRAILINGSPACE(m0)) {
				/* pad */
				m0->m_len += (8 - extra);
				m0->m_pkthdr.len += (8 - extra);
			} else {
				/* truncate */
				m0->m_pkthdr.len -= extra;
				m0->m_len -= extra;
			}
		}
		len = m0->m_pkthdr.len + sizeof(*nd_opt_rh);
		m0->m_pkthdr.len = m0->m_len = len - sizeof(*nd_opt_rh);
	}

	nd_opt_rh = (struct nd_opt_rd_hdr *)p;
	bzero(nd_opt_rh, sizeof(*nd_opt_rh));
	nd_opt_rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
	nd_opt_rh->nd_opt_rh_len = len >> 3;
	p += sizeof(*nd_opt_rh);
	m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

	/* connect m0 to m */
	m->m_next = m0;
	m->m_pkthdr.len = m->m_len + m0->m_len;
    }
noredhdropt:;

	/* XXX: clear embedded link IDs in the inner header */
	in6_clearscope(&sip6->ip6_src);
	in6_clearscope(&sip6->ip6_dst);
	in6_clearscope(&nd_rd->nd_rd_target);
	in6_clearscope(&nd_rd->nd_rd_dst);

	ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(struct ip6_hdr));

	nd_rd->nd_rd_cksum = 0;
	nd_rd->nd_rd_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), ntohs(ip6->ip6_plen));

	/* send the packet to outside... */
	ip6oa.ip6oa_boundif = ifp->if_index;
	ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;

	ip6_output(m, NULL, NULL, IPV6_OUTARGS, NULL, &outif, &ip6oa);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_redirect);
		ifnet_release(outif);
	}
	icmp6stat.icp6s_outhist[ND_REDIRECT]++;

	return;

fail:
	if (rt != NULL)
		RT_UNLOCK(rt);
	if (m)
		m_freem(m);
	if (m0)
		m_freem(m0);
}

/*
 * ICMPv6 socket option processing.
 */
int
icmp6_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	int optlen;
	struct inpcb *inp = sotoinpcb(so);
	int level, op, optname;

	if (sopt) {
		level = sopt->sopt_level;
		op = sopt->sopt_dir;
		optname = sopt->sopt_name;
		optlen = sopt->sopt_valsize;
	} else
		level = op = optname = optlen = 0;

	if (level != IPPROTO_ICMPV6) {
		return EINVAL;
	}

	switch (op) {
	case PRCO_SETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter *p;

			if (optlen != 0 && optlen != sizeof(*p)) {
				error = EMSGSIZE;
				break;
			}
			if (inp->in6p_icmp6filt == NULL) {
				error = EINVAL;
				break;
			}

			if (optlen == 0) {
				/* According to RFC 3542, an installed filter can be
				 * cleared by issuing a setsockopt for ICMP6_FILTER
				 * with a zero length.
				 */
				ICMP6_FILTER_SETPASSALL(inp->in6p_icmp6filt);
			} else {
				error = sooptcopyin(sopt, inp->in6p_icmp6filt, optlen,
					optlen);
			}
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	case PRCO_GETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			if (inp->in6p_icmp6filt == NULL) {
				error = EINVAL;
				break;
			}
			error = sooptcopyout(sopt, inp->in6p_icmp6filt,
					min(sizeof(struct icmp6_filter), optlen));
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}

	return(error);
}

/*
 * ICMPv6 socket datagram option processing.
 */
int
icmp6_dgram_ctloutput(struct socket *so, struct sockopt *sopt)
{
	if (kauth_cred_issuser(so->so_cred))
		return icmp6_ctloutput(so, sopt);

	if (sopt->sopt_level == IPPROTO_ICMPV6) {
		switch (sopt->sopt_name) {
			case ICMP6_FILTER:
				return icmp6_ctloutput(so, sopt);
			default:
				return EPERM;
		}
	}

	if (sopt->sopt_level != IPPROTO_IPV6)
		return EINVAL;

	switch (sopt->sopt_name) {
		case IPV6_UNICAST_HOPS:
		case IPV6_CHECKSUM:
		case IPV6_V6ONLY:
		case IPV6_USE_MIN_MTU:
		case IPV6_RECVRTHDR:
		case IPV6_RECVPKTINFO:
		case IPV6_RECVHOPLIMIT:
		case IPV6_PATHMTU:
		case IPV6_PKTINFO:
		case IPV6_HOPLIMIT:
		case IPV6_HOPOPTS:
		case IPV6_DSTOPTS:
		case IPV6_MULTICAST_IF:
		case IPV6_MULTICAST_HOPS:
		case IPV6_MULTICAST_LOOP:
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case IPV6_PORTRANGE:
		case IPV6_IPSEC_POLICY:
		case IPV6_RECVTCLASS:
		case IPV6_TCLASS:
		case IPV6_2292PKTOPTIONS:
		case IPV6_2292PKTINFO:
		case IPV6_2292HOPLIMIT:
		case IPV6_2292HOPOPTS:
		case IPV6_2292DSTOPTS:
		case IPV6_2292RTHDR:
		case IPV6_BOUND_IF:
		case IPV6_NO_IFT_CELLULAR:

			return ip6_ctloutput(so, sopt);

		default:
			return EPERM;
	}
}

__private_extern__ int
icmp6_dgram_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct proc *p)
{
#pragma unused(flags, p)
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 tmp;
	struct sockaddr_in6 *dst = (struct sockaddr_in6 *)(void *)nam;
	struct icmp6_hdr *icmp6;

	if (inp == NULL
#if NECP
		|| (necp_socket_should_use_flow_divert(inp))
#endif /* NECP */
		) {
		error = (inp == NULL ? EINVAL : EPROTOTYPE);
		goto bad;
	}

	if (kauth_cred_issuser(so->so_cred))
		return (rip6_output(m, so, SIN6(nam), control, 0));

	/* always copy sockaddr to avoid overwrites */
	if (so->so_state & SS_ISCONNECTED) {
		if (nam != NULL) {
			error = EISCONN;
			goto bad;
		}
		/* XXX */
		bzero(&tmp, sizeof(tmp));
		tmp.sin6_family = AF_INET6;
		tmp.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&inp->in6p_faddr, &tmp.sin6_addr,
			  sizeof(struct in6_addr));
		dst = &tmp;
	} else {
		if (nam == NULL) {
			error = ENOTCONN;
			goto bad;
		}
		tmp = *(struct sockaddr_in6 *)(void *)nam;
		dst = &tmp;
	}

	/*
	 * For an ICMPv6 packet, we should know its type and code
	 */
	if (SOCK_PROTO(so) == IPPROTO_ICMPV6) {
		if (m->m_len < sizeof(struct icmp6_hdr) &&
			(m = m_pullup(m, sizeof(struct icmp6_hdr))) == NULL) {
				error = ENOBUFS;
				goto bad;
		}
		icmp6 = mtod(m, struct icmp6_hdr *);

		/*
		 * Allow only to send echo request and node information request
		 * See RFC 2463 for Echo Request Message format
		 */
		if ((icmp6->icmp6_type == ICMP6_ECHO_REQUEST &&
		    icmp6->icmp6_code == 0) ||
		    (icmp6->icmp6_type == ICMP6_NI_QUERY &&
		    (icmp6->icmp6_code == ICMP6_NI_SUBJ_IPV6 ||
		    icmp6->icmp6_code == ICMP6_NI_SUBJ_FQDN))) {
			/* Good */
			;
		} else {
			error = EPERM;
			goto bad;
		}
	}

#if ENABLE_DEFAULT_SCOPE
	if (dst->sin6_scope_id == 0) {  /* not change if specified  */
		dst->sin6_scope_id = scope6_addr2default(&dst->sin6_addr);
	}
#endif

	return (rip6_output(m, so, dst, control, 0));
bad:
	VERIFY(error != 0);

	if (m != NULL)
		m_freem(m);
	if (control != NULL)
		m_freem(control);

	return (error);
}

/* Like rip6_attach but without root privilege enforcement */
__private_extern__ int
icmp6_dgram_attach(struct socket *so, int proto, struct proc *p)
{
        struct inpcb *inp;
        int error;

        inp = sotoinpcb(so);
        if (inp)
                panic("icmp6_dgram_attach");

		if (proto != IPPROTO_ICMPV6)
			return EINVAL;

        error = soreserve(so, rip_sendspace, rip_recvspace);
        if (error)
                return error;
        error = in_pcballoc(so, &ripcbinfo, p);
        if (error)
                return error;
        inp = (struct inpcb *)so->so_pcb;
        inp->inp_vflag |= INP_IPV6;
        inp->in6p_ip6_nxt = IPPROTO_ICMPV6;
        inp->in6p_hops = -1;    /* use kernel default */
        inp->in6p_cksum = -1;
        MALLOC(inp->in6p_icmp6filt, struct icmp6_filter *,
               sizeof(struct icmp6_filter), M_PCB, M_WAITOK);
        if (inp->in6p_icmp6filt == NULL)
                return (ENOMEM);
        ICMP6_FILTER_SETPASSALL(inp->in6p_icmp6filt);
        return 0;
}


/*
 * Perform rate limit check.
 * Returns 0 if it is okay to send the icmp6 packet.
 * Returns 1 if the router SHOULD NOT send this icmp6 packet due to rate
 * limitation.
 *
 * XXX per-destination check necessary?
 */
static int
icmp6_ratelimit(
	__unused const struct in6_addr *dst,	/* not used at this moment */
	const int type,
	__unused const int code)
{
	int ret;

	ret = 0;	/* okay to send */

	/* PPS limit */
	if (type == ND_ROUTER_ADVERT) {
		if (!ppsratecheck(&icmp6rappslim_last, &icmp6rapps_count,
		    icmp6rappslim))
			ret++;
	} else if (!ppsratecheck(&icmp6errppslim_last, &icmp6errpps_count,
	    icmp6errppslim)) {
		/* The packet is subject to rate limit */
		ret++;
	}

	return ret;
}
