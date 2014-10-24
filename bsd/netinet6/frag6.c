/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/frag6.c,v 1.2.2.5 2001/07/03 11:01:50 ume Exp $	*/
/*	$KAME: frag6.c,v 1.31 2001/05/17 13:45:34 jinmei Exp $	*/

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
#include <sys/malloc.h>
#include <sys/mcache.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <kern/queue.h>
#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <net/net_osdep.h>
#include <dev/random/randomdev.h>

/*
 * Define it to get a correct behavior on per-interface statistics.
 */
#define IN6_IFSTAT_STRICT

MBUFQ_HEAD(fq6_head);

static void frag6_save_context(struct mbuf *, int);
static void frag6_scrub_context(struct mbuf *);
static int frag6_restore_context(struct mbuf *);

static void frag6_icmp6_paramprob_error(struct fq6_head *);
static void frag6_icmp6_timeex_error(struct fq6_head *);

static void frag6_enq(struct ip6asfrag *, struct ip6asfrag *);
static void frag6_deq(struct ip6asfrag *);
static void frag6_insque(struct ip6q *, struct ip6q *);
static void frag6_remque(struct ip6q *);
static void frag6_freef(struct ip6q *, struct fq6_head *, struct fq6_head *);

static int frag6_timeout_run;		/* frag6 timer is scheduled to run */
static void frag6_timeout(void *);
static void frag6_sched_timeout(void);

static struct ip6q *ip6q_alloc(int);
static void ip6q_free(struct ip6q *);
static void ip6q_updateparams(void);
static struct ip6asfrag *ip6af_alloc(int);
static void ip6af_free(struct ip6asfrag *);

decl_lck_mtx_data(static, ip6qlock);
static lck_attr_t	*ip6qlock_attr;
static lck_grp_t	*ip6qlock_grp;
static lck_grp_attr_t	*ip6qlock_grp_attr;

/* IPv6 fragment reassembly queues (protected by ip6qlock) */
static struct ip6q ip6q;		/* ip6 reassembly queues */
static int ip6_maxfragpackets;		/* max packets in reass queues */
static u_int32_t frag6_nfragpackets;	/* # of packets in reass queues */
static int ip6_maxfrags;		/* max fragments in reass queues */
static u_int32_t frag6_nfrags;		/* # of fragments in reass queues */
static u_int32_t ip6q_limit;		/* ip6q allocation limit */
static u_int32_t ip6q_count;		/* current # of allocated ip6q's */
static u_int32_t ip6af_limit;		/* ip6asfrag allocation limit */
static u_int32_t ip6af_count;		/* current # of allocated ip6asfrag's */

static int sysctl_maxfragpackets SYSCTL_HANDLER_ARGS;
static int sysctl_maxfrags SYSCTL_HANDLER_ARGS;

SYSCTL_DECL(_net_inet6_ip6);

SYSCTL_PROC(_net_inet6_ip6, IPV6CTL_MAXFRAGPACKETS, maxfragpackets,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_maxfragpackets, 0,
    sysctl_maxfragpackets, "I",
    "Maximum number of IPv6 fragment reassembly queue entries");

SYSCTL_UINT(_net_inet6_ip6, OID_AUTO, fragpackets,
    CTLFLAG_RD | CTLFLAG_LOCKED, &frag6_nfragpackets, 0,
    "Current number of IPv6 fragment reassembly queue entries");

SYSCTL_PROC(_net_inet6_ip6, IPV6CTL_MAXFRAGS, maxfrags,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_maxfrags, 0,
    sysctl_maxfrags, "I", "Maximum number of IPv6 fragments allowed");

/*
 * Initialise reassembly queue and fragment identifier.
 */
void
frag6_init(void)
{
	/* ip6q_alloc() uses mbufs for IPv6 fragment queue structures */
	_CASSERT(sizeof (struct ip6q) <= _MLEN);
	/* ip6af_alloc() uses mbufs for IPv6 fragment queue structures */
	_CASSERT(sizeof (struct ip6asfrag) <= _MLEN);

	/* IPv6 fragment reassembly queue lock */
	ip6qlock_grp_attr  = lck_grp_attr_alloc_init();
	ip6qlock_grp = lck_grp_alloc_init("ip6qlock", ip6qlock_grp_attr);
	ip6qlock_attr = lck_attr_alloc_init();
	lck_mtx_init(&ip6qlock, ip6qlock_grp, ip6qlock_attr);

	lck_mtx_lock(&ip6qlock);
	/* Initialize IPv6 reassembly queue. */
	ip6q.ip6q_next = ip6q.ip6q_prev = &ip6q;

	/* same limits as IPv4 */
	ip6_maxfragpackets = nmbclusters / 32;
	ip6_maxfrags = ip6_maxfragpackets * 2;
	ip6q_updateparams();
	lck_mtx_unlock(&ip6qlock);
}

static void
frag6_save_context(struct mbuf *m, int val)
{
	m->m_pkthdr.pkt_hdr = (void *)(uintptr_t)val;
}

static void
frag6_scrub_context(struct mbuf *m)
{
	m->m_pkthdr.pkt_hdr = NULL;
}

static int
frag6_restore_context(struct mbuf *m)
{
	return ((int)m->m_pkthdr.pkt_hdr);
}

/*
 * Send any deferred ICMP param problem error messages; caller must not be
 * holding ip6qlock and is expected to have saved the per-packet parameter
 * value via frag6_save_context().
 */
static void
frag6_icmp6_paramprob_error(struct fq6_head *diq6)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_NOTOWNED);

	if (!MBUFQ_EMPTY(diq6)) {
		struct mbuf *merr, *merr_tmp;
		int param;
		MBUFQ_FOREACH_SAFE(merr, diq6, merr_tmp) {
			MBUFQ_REMOVE(diq6, merr);
			MBUFQ_NEXT(merr) = NULL;
			param = frag6_restore_context(merr);
			frag6_scrub_context(merr);
			icmp6_error(merr, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_HEADER, param);
		}
	}
}

/*
 * Send any deferred ICMP time exceeded error messages;
 * caller must not be holding ip6qlock.
 */
static void
frag6_icmp6_timeex_error(struct fq6_head *diq6)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_NOTOWNED);

	if (!MBUFQ_EMPTY(diq6)) {
		struct mbuf *m, *m_tmp;
		MBUFQ_FOREACH_SAFE(m, diq6, m_tmp) {
			MBUFQ_REMOVE(diq6, m);
			MBUFQ_NEXT(m) = NULL;
			icmp6_error(m, ICMP6_TIME_EXCEEDED,
			    ICMP6_TIME_EXCEED_REASSEMBLY, 0);
		}
	}
}

/*
 * In RFC2460, fragment and reassembly rule do not agree with each other,
 * in terms of next header field handling in fragment header.
 * While the sender will use the same value for all of the fragmented packets,
 * receiver is suggested not to check the consistency.
 *
 * fragment rule (p20):
 *	(2) A Fragment header containing:
 *	The Next Header value that identifies the first header of
 *	the Fragmentable Part of the original packet.
 *		-> next header field is same for all fragments
 *
 * reassembly rule (p21):
 *	The Next Header field of the last header of the Unfragmentable
 *	Part is obtained from the Next Header field of the first
 *	fragment's Fragment header.
 *		-> should grab it from the first fragment only
 *
 * The following note also contradicts with fragment rule - noone is going to
 * send different fragment with different next header field.
 *
 * additional note (p22):
 *	The Next Header values in the Fragment headers of different
 *	fragments of the same original packet may differ.  Only the value
 *	from the Offset zero fragment packet is used for reassembly.
 *		-> should grab it from the first fragment only
 *
 * There is no explicit reason given in the RFC.  Historical reason maybe?
 */
/*
 * Fragment input
 */
int
frag6_input(struct mbuf **mp, int *offp, int proto)
{
#pragma unused(proto)
	struct mbuf *m = *mp, *t;
	struct ip6_hdr *ip6;
	struct ip6_frag *ip6f;
	struct ip6q *q6;
	struct ip6asfrag *af6, *ip6af, *af6dwn;
	int offset = *offp, nxt, i, next;
	int first_frag = 0;
	int fragoff, frgpartlen;	/* must be larger than u_int16_t */
	struct ifnet *dstifp = NULL;
	u_int8_t ecn, ecn0;
	uint32_t csum, csum_flags;
	struct fq6_head diq6;
	int locked = 0;

	VERIFY(m->m_flags & M_PKTHDR);

	MBUFQ_INIT(&diq6);	/* for deferred ICMP param problem errors */

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip6 = mtod(m, struct ip6_hdr *);
	IP6_EXTHDR_CHECK(m, offset, sizeof(struct ip6_frag), goto done);
	ip6f = (struct ip6_frag *)((caddr_t)ip6 + offset);

#ifdef IN6_IFSTAT_STRICT
	/* find the destination interface of the packet. */
	if (m->m_pkthdr.pkt_flags & PKTF_IFAINFO) {
		uint32_t idx;

		if (ip6_getdstifaddr_info(m, &idx, NULL) == 0) {
			if (idx > 0 && idx <= if_index) {
				ifnet_head_lock_shared();
				dstifp = ifindex2ifnet[idx];
				ifnet_head_done();
			}
		}
	}
#endif /* IN6_IFSTAT_STRICT */

	/* we are violating the spec, this may not be the dst interface */
	if (dstifp == NULL)
		dstifp = m->m_pkthdr.rcvif;

	/* jumbo payload can't contain a fragment header */
	if (ip6->ip6_plen == 0) {
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER, offset);
		in6_ifstat_inc(dstifp, ifs6_reass_fail);
		m = NULL;
		goto done;
	}

	/*
	 * check whether fragment packet's fragment length is
	 * multiple of 8 octets.
	 * sizeof(struct ip6_frag) == 8
	 * sizeof(struct ip6_hdr) = 40
	 */
	if ((ip6f->ip6f_offlg & IP6F_MORE_FRAG) &&
	    (((ntohs(ip6->ip6_plen) - offset) & 0x7) != 0)) {
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    offsetof(struct ip6_hdr, ip6_plen));
		in6_ifstat_inc(dstifp, ifs6_reass_fail);
		m = NULL;
		goto done;
	}

	/* If ip6_maxfragpackets or ip6_maxfrags is 0, never accept fragments */
	if (ip6_maxfragpackets == 0 || ip6_maxfrags == 0) {
		ip6stat.ip6s_fragments++;
		ip6stat.ip6s_fragdropped++;
		in6_ifstat_inc(dstifp, ifs6_reass_fail);
		m_freem(m);
		m = NULL;
		goto done;
	}

	/* offset now points to data portion */
	offset += sizeof(struct ip6_frag);

	/*
	 * Leverage partial checksum offload for simple UDP/IP fragments,
	 * as that is the most common case.
	 *
	 * Perform 1's complement adjustment of octets that got included/
	 * excluded in the hardware-calculated checksum value.
	 */
	if (ip6f->ip6f_nxt == IPPROTO_UDP &&
	    offset == (sizeof (*ip6) + sizeof (*ip6f)) &&
	    (m->m_pkthdr.csum_flags &
	    (CSUM_DATA_VALID | CSUM_PARTIAL | CSUM_PSEUDO_HDR)) ==
	    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
		uint32_t start;

		start = m->m_pkthdr.csum_rx_start;
		csum = m->m_pkthdr.csum_rx_val;

		if (start != offset) {
			uint16_t s, d;

			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
				s = ip6->ip6_src.s6_addr16[1];
				ip6->ip6_src.s6_addr16[1] = 0 ;
			}
			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst)) {
				d = ip6->ip6_dst.s6_addr16[1];
				ip6->ip6_dst.s6_addr16[1] = 0;
			}

			/* callee folds in sum */
			csum = m_adj_sum16(m, start, offset, csum);

			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src))
				ip6->ip6_src.s6_addr16[1] = s;
			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst))
				ip6->ip6_dst.s6_addr16[1] = d;

		}
		csum_flags = m->m_pkthdr.csum_flags;
	} else {
		csum = 0;
		csum_flags = 0;
	}

	/* Invalidate checksum */
	m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;

	ip6stat.ip6s_fragments++;
	in6_ifstat_inc(dstifp, ifs6_reass_reqd);

	lck_mtx_lock(&ip6qlock);
	locked = 1;

	for (q6 = ip6q.ip6q_next; q6 != &ip6q; q6 = q6->ip6q_next)
		if (ip6f->ip6f_ident == q6->ip6q_ident &&
		    IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &q6->ip6q_src) &&
		    IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &q6->ip6q_dst))
			break;

	if (q6 == &ip6q) {
		/*
		 * the first fragment to arrive, create a reassembly queue.
		 */
		first_frag = 1;

		q6 = ip6q_alloc(M_DONTWAIT);
		if (q6 == NULL)
			goto dropfrag;

		frag6_insque(q6, &ip6q);
		frag6_nfragpackets++;

		/* ip6q_nxt will be filled afterwards, from 1st fragment */
		q6->ip6q_down	= q6->ip6q_up = (struct ip6asfrag *)q6;
#ifdef notyet
		q6->ip6q_nxtp	= (u_char *)nxtp;
#endif
		q6->ip6q_ident	= ip6f->ip6f_ident;
		q6->ip6q_ttl	= IPV6_FRAGTTL;
		q6->ip6q_src	= ip6->ip6_src;
		q6->ip6q_dst	= ip6->ip6_dst;
		q6->ip6q_ecn	=
		    (ntohl(ip6->ip6_flow) >> 20) & IPTOS_ECN_MASK;
		q6->ip6q_unfrglen = -1;	/* The 1st fragment has not arrived. */

		q6->ip6q_nfrag = 0;

		/*
		 * If the first fragment has valid checksum offload
		 * info, the rest of fragments are eligible as well.
		 */
		if (csum_flags != 0) {
			q6->ip6q_csum = csum;
			q6->ip6q_csum_flags = csum_flags;
		}
	}

	/*
	 * If it's the 1st fragment, record the length of the
	 * unfragmentable part and the next header of the fragment header.
	 */
	fragoff = ntohs(ip6f->ip6f_offlg & IP6F_OFF_MASK);
	if (fragoff == 0) {
		q6->ip6q_unfrglen = offset - sizeof(struct ip6_hdr) -
		    sizeof(struct ip6_frag);
		q6->ip6q_nxt = ip6f->ip6f_nxt;
	}

	/*
	 * Check that the reassembled packet would not exceed 65535 bytes
	 * in size.
	 * If it would exceed, discard the fragment and return an ICMP error.
	 */
	frgpartlen = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen) - offset;
	if (q6->ip6q_unfrglen >= 0) {
		/* The 1st fragment has already arrived. */
		if (q6->ip6q_unfrglen + fragoff + frgpartlen > IPV6_MAXPACKET) {
			lck_mtx_unlock(&ip6qlock);
			locked = 0;
			icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
			    offset - sizeof(struct ip6_frag) +
			    offsetof(struct ip6_frag, ip6f_offlg));
			m = NULL;
			goto done;
		}
	} else if (fragoff + frgpartlen > IPV6_MAXPACKET) {
		lck_mtx_unlock(&ip6qlock);
		locked = 0;
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    offset - sizeof(struct ip6_frag) +
		    offsetof(struct ip6_frag, ip6f_offlg));
		m = NULL;
		goto done;
	}
	/*
	 * If it's the first fragment, do the above check for each
	 * fragment already stored in the reassembly queue.
	 */
	if (fragoff == 0) {
		for (af6 = q6->ip6q_down; af6 != (struct ip6asfrag *)q6;
		     af6 = af6dwn) {
			af6dwn = af6->ip6af_down;

			if (q6->ip6q_unfrglen + af6->ip6af_off + af6->ip6af_frglen >
			    IPV6_MAXPACKET) {
				struct mbuf *merr = IP6_REASS_MBUF(af6);
				struct ip6_hdr *ip6err;
				int erroff = af6->ip6af_offset;

				/* dequeue the fragment. */
				frag6_deq(af6);
				ip6af_free(af6);

				/* adjust pointer. */
				ip6err = mtod(merr, struct ip6_hdr *);

				/*
				 * Restore source and destination addresses
				 * in the erroneous IPv6 header.
				 */
				ip6err->ip6_src = q6->ip6q_src;
				ip6err->ip6_dst = q6->ip6q_dst;

				frag6_save_context(merr,
				    erroff - sizeof (struct ip6_frag) +
				    offsetof(struct ip6_frag, ip6f_offlg));

				MBUFQ_ENQUEUE(&diq6, merr);
			}
		}
	}

	ip6af = ip6af_alloc(M_DONTWAIT);
	if (ip6af == NULL)
		goto dropfrag;

	ip6af->ip6af_mff = ip6f->ip6f_offlg & IP6F_MORE_FRAG;
	ip6af->ip6af_off = fragoff;
	ip6af->ip6af_frglen = frgpartlen;
	ip6af->ip6af_offset = offset;
	IP6_REASS_MBUF(ip6af) = m;

	if (first_frag) {
		af6 = (struct ip6asfrag *)q6;
		goto insert;
	}

	/*
	 * Handle ECN by comparing this segment with the first one;
	 * if CE is set, do not lose CE.
	 * drop if CE and not-ECT are mixed for the same packet.
	 */
	ecn = (ntohl(ip6->ip6_flow) >> 20) & IPTOS_ECN_MASK;
	ecn0 = q6->ip6q_ecn;
	if (ecn == IPTOS_ECN_CE) {
		if (ecn0 == IPTOS_ECN_NOTECT) {
			ip6af_free(ip6af);
			goto dropfrag;
		}
		if (ecn0 != IPTOS_ECN_CE)
			q6->ip6q_ecn = IPTOS_ECN_CE;
	}
	if (ecn == IPTOS_ECN_NOTECT && ecn0 != IPTOS_ECN_NOTECT) {
		ip6af_free(ip6af);
		goto dropfrag;
	}

	/*
	 * Find a segment which begins after this one does.
	 */
	for (af6 = q6->ip6q_down; af6 != (struct ip6asfrag *)q6;
	     af6 = af6->ip6af_down)
		if (af6->ip6af_off > ip6af->ip6af_off)
			break;

#if 0
	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 *
	 * If some of the data is dropped from the preceding
	 * segment, then it's checksum is invalidated.
	 */
	if (af6->ip6af_up != (struct ip6asfrag *)q6) {
		i = af6->ip6af_up->ip6af_off + af6->ip6af_up->ip6af_frglen
			- ip6af->ip6af_off;
		if (i > 0) {
			if (i >= ip6af->ip6af_frglen)
				goto dropfrag;
			m_adj(IP6_REASS_MBUF(ip6af), i);
			q6->ip6q_csum_flags = 0;
			ip6af->ip6af_off += i;
			ip6af->ip6af_frglen -= i;
		}
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (af6 != (struct ip6asfrag *)q6 &&
	       ip6af->ip6af_off + ip6af->ip6af_frglen > af6->ip6af_off) {
		i = (ip6af->ip6af_off + ip6af->ip6af_frglen) - af6->ip6af_off;
		if (i < af6->ip6af_frglen) {
			af6->ip6af_frglen -= i;
			af6->ip6af_off += i;
			m_adj(IP6_REASS_MBUF(af6), i);
			q6->ip6q_csum_flags = 0;
			break;
		}
		af6 = af6->ip6af_down;
		m_freem(IP6_REASS_MBUF(af6->ip6af_up));
		frag6_deq(af6->ip6af_up);
	}
#else
	/*
	 * If the incoming framgent overlaps some existing fragments in
	 * the reassembly queue, drop it, since it is dangerous to override
	 * existing fragments from a security point of view.
	 * We don't know which fragment is the bad guy - here we trust
	 * fragment that came in earlier, with no real reason.
	 *
	 * Note: due to changes after disabling this part, mbuf passed to
	 * m_adj() below now does not meet the requirement.
	 */
	if (af6->ip6af_up != (struct ip6asfrag *)q6) {
		i = af6->ip6af_up->ip6af_off + af6->ip6af_up->ip6af_frglen
			- ip6af->ip6af_off;
		if (i > 0) {
#if 0				/* suppress the noisy log */
			log(LOG_ERR, "%d bytes of a fragment from %s "
			    "overlaps the previous fragment\n",
			    i, ip6_sprintf(&q6->ip6q_src));
#endif
			ip6af_free(ip6af);
			goto dropfrag;
		}
	}
	if (af6 != (struct ip6asfrag *)q6) {
		i = (ip6af->ip6af_off + ip6af->ip6af_frglen) - af6->ip6af_off;
		if (i > 0) {
#if 0				/* suppress the noisy log */
			log(LOG_ERR, "%d bytes of a fragment from %s "
			    "overlaps the succeeding fragment",
			    i, ip6_sprintf(&q6->ip6q_src));
#endif
			ip6af_free(ip6af);
			goto dropfrag;
		}
	}
#endif

	/*
	 * If this fragment contains similar checksum offload info
	 * as that of the existing ones, accumulate checksum.  Otherwise,
	 * invalidate checksum offload info for the entire datagram.
	 */
	if (csum_flags != 0 && csum_flags == q6->ip6q_csum_flags)
		q6->ip6q_csum += csum;
	else if (q6->ip6q_csum_flags != 0)
		q6->ip6q_csum_flags = 0;

insert:

	/*
	 * Stick new segment in its place;
	 * check for complete reassembly.
	 * Move to front of packet queue, as we are
	 * the most recently active fragmented packet.
	 */
	frag6_enq(ip6af, af6->ip6af_up);
	frag6_nfrags++;
	q6->ip6q_nfrag++;
#if 0 /* xxx */
	if (q6 != ip6q.ip6q_next) {
		frag6_remque(q6);
		frag6_insque(q6, &ip6q);
	}
#endif
	next = 0;
	for (af6 = q6->ip6q_down; af6 != (struct ip6asfrag *)q6;
	     af6 = af6->ip6af_down) {
		if (af6->ip6af_off != next) {
			lck_mtx_unlock(&ip6qlock);
			locked = 0;
			m = NULL;
			goto done;
		}
		next += af6->ip6af_frglen;
	}
	if (af6->ip6af_up->ip6af_mff) {
		lck_mtx_unlock(&ip6qlock);
		locked = 0;
		m = NULL;
		goto done;
	}

	/*
	 * Reassembly is complete; concatenate fragments.
	 */
	ip6af = q6->ip6q_down;
	t = m = IP6_REASS_MBUF(ip6af);
	af6 = ip6af->ip6af_down;
	frag6_deq(ip6af);
	while (af6 != (struct ip6asfrag *)q6) {
		af6dwn = af6->ip6af_down;
		frag6_deq(af6);
		while (t->m_next)
			t = t->m_next;
		t->m_next = IP6_REASS_MBUF(af6);
		m_adj(t->m_next, af6->ip6af_offset);
		ip6af_free(af6);
		af6 = af6dwn;
	}

	/*
	 * Store partial hardware checksum info from the fragment queue;
	 * the receive start offset is set to 40 bytes (see code at the
	 * top of this routine.)
	 */
	if (q6->ip6q_csum_flags != 0) {
		csum = q6->ip6q_csum;

		ADDCARRY(csum);

		m->m_pkthdr.csum_rx_val = csum;
		m->m_pkthdr.csum_rx_start = sizeof (struct ip6_hdr);
		m->m_pkthdr.csum_flags = q6->ip6q_csum_flags;
	} else if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		/* loopback checksums are always OK */
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags &= ~CSUM_PARTIAL;
		m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
	}

	/* adjust offset to point where the original next header starts */
	offset = ip6af->ip6af_offset - sizeof(struct ip6_frag);
	ip6af_free(ip6af);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons((u_short)next + offset - sizeof(struct ip6_hdr));
	ip6->ip6_src = q6->ip6q_src;
	ip6->ip6_dst = q6->ip6q_dst;
	if (q6->ip6q_ecn == IPTOS_ECN_CE)
		ip6->ip6_flow |= htonl(IPTOS_ECN_CE << 20);

	nxt = q6->ip6q_nxt;
#ifdef notyet
	*q6->ip6q_nxtp = (u_char)(nxt & 0xff);
#endif

	/* Delete frag6 header */
	if (m->m_len >= offset + sizeof(struct ip6_frag)) {
		/* This is the only possible case with !PULLDOWN_TEST */
		ovbcopy((caddr_t)ip6, (caddr_t)ip6 + sizeof(struct ip6_frag),
		    offset);
		m->m_data += sizeof(struct ip6_frag);
		m->m_len -= sizeof(struct ip6_frag);
	} else {
		/* this comes with no copy if the boundary is on cluster */
		if ((t = m_split(m, offset, M_DONTWAIT)) == NULL) {
			frag6_remque(q6);
			frag6_nfragpackets--;
			frag6_nfrags -= q6->ip6q_nfrag;
			ip6q_free(q6);
			goto dropfrag;
		}
		m_adj(t, sizeof(struct ip6_frag));
		m_cat(m, t);
	}

	/*
	 * Store NXT to the original.
	 */
	{
		char *prvnxtp = ip6_get_prevhdr(m, offset); /* XXX */
		*prvnxtp = nxt;
	}

	frag6_remque(q6);
	frag6_nfragpackets--;
	frag6_nfrags -= q6->ip6q_nfrag;
	ip6q_free(q6);

	if (m->m_flags & M_PKTHDR)	/* Isn't it always true? */
		m_fixhdr(m);

	ip6stat.ip6s_reassembled++;

	/*
	 * Tell launch routine the next header
	 */
	*mp = m;
	*offp = offset;

	/* arm the purge timer if not already and if there's work to do */
	frag6_sched_timeout();
	lck_mtx_unlock(&ip6qlock);
	in6_ifstat_inc(dstifp, ifs6_reass_ok);
	frag6_icmp6_paramprob_error(&diq6);
	VERIFY(MBUFQ_EMPTY(&diq6));
	return (nxt);

done:
	VERIFY(m == NULL);
	if (!locked) {
		if (frag6_nfragpackets == 0) {
			frag6_icmp6_paramprob_error(&diq6);
			VERIFY(MBUFQ_EMPTY(&diq6));
			return (IPPROTO_DONE);
		}
		lck_mtx_lock(&ip6qlock);
	}
	/* arm the purge timer if not already and if there's work to do */
	frag6_sched_timeout();
	lck_mtx_unlock(&ip6qlock);
	frag6_icmp6_paramprob_error(&diq6);
	VERIFY(MBUFQ_EMPTY(&diq6));
	return (IPPROTO_DONE);

dropfrag:
	ip6stat.ip6s_fragdropped++;
	/* arm the purge timer if not already and if there's work to do */
	frag6_sched_timeout();
	lck_mtx_unlock(&ip6qlock);
	in6_ifstat_inc(dstifp, ifs6_reass_fail);
	m_freem(m);
	frag6_icmp6_paramprob_error(&diq6);
	VERIFY(MBUFQ_EMPTY(&diq6));
	return (IPPROTO_DONE);
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
frag6_freef(struct ip6q *q6, struct fq6_head *dfq6, struct fq6_head *diq6)
{
	struct ip6asfrag *af6, *down6;

	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	for (af6 = q6->ip6q_down; af6 != (struct ip6asfrag *)q6;
	     af6 = down6) {
		struct mbuf *m = IP6_REASS_MBUF(af6);

		down6 = af6->ip6af_down;
		frag6_deq(af6);

		/*
		 * Return ICMP time exceeded error for the 1st fragment.
		 * Just free other fragments.
		 */
		if (af6->ip6af_off == 0) {
			struct ip6_hdr *ip6;

			/* adjust pointer */
			ip6 = mtod(m, struct ip6_hdr *);

			/* restore source and destination addresses */
			ip6->ip6_src = q6->ip6q_src;
			ip6->ip6_dst = q6->ip6q_dst;

			MBUFQ_ENQUEUE(diq6, m);
		} else {
			MBUFQ_ENQUEUE(dfq6, m);
		}
		ip6af_free(af6);

	}
	frag6_remque(q6);
	frag6_nfragpackets--;
	frag6_nfrags -= q6->ip6q_nfrag;
	ip6q_free(q6);
}

/*
 * Put an ip fragment on a reassembly chain.
 * Like insque, but pointers in middle of structure.
 */
void
frag6_enq(struct ip6asfrag *af6, struct ip6asfrag *up6)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	af6->ip6af_up = up6;
	af6->ip6af_down = up6->ip6af_down;
	up6->ip6af_down->ip6af_up = af6;
	up6->ip6af_down = af6;
}

/*
 * To frag6_enq as remque is to insque.
 */
void
frag6_deq(struct ip6asfrag *af6)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	af6->ip6af_up->ip6af_down = af6->ip6af_down;
	af6->ip6af_down->ip6af_up = af6->ip6af_up;
}

void
frag6_insque(struct ip6q *new, struct ip6q *old)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	new->ip6q_prev = old;
	new->ip6q_next = old->ip6q_next;
	old->ip6q_next->ip6q_prev= new;
	old->ip6q_next = new;
}

void
frag6_remque(struct ip6q *p6)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	p6->ip6q_prev->ip6q_next = p6->ip6q_next;
	p6->ip6q_next->ip6q_prev = p6->ip6q_prev;
}

/*
 * IPv6 reassembling timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
static void
frag6_timeout(void *arg)
{
#pragma unused(arg)
	struct fq6_head dfq6, diq6;
	struct ip6q *q6;

	MBUFQ_INIT(&dfq6);	/* for deferred frees */
	MBUFQ_INIT(&diq6);	/* for deferred ICMP time exceeded errors */

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	lck_mtx_lock(&ip6qlock);
	q6 = ip6q.ip6q_next;
	if (q6)
		while (q6 != &ip6q) {
			--q6->ip6q_ttl;
			q6 = q6->ip6q_next;
			if (q6->ip6q_prev->ip6q_ttl == 0) {
				ip6stat.ip6s_fragtimeout++;
				/* XXX in6_ifstat_inc(ifp, ifs6_reass_fail) */
				frag6_freef(q6->ip6q_prev, &dfq6, &diq6);
			}
		}
	/*
	 * If we are over the maximum number of fragments
	 * (due to the limit being lowered), drain off
	 * enough to get down to the new limit.
	 */
	if (ip6_maxfragpackets >= 0) {
		while (frag6_nfragpackets > (unsigned)ip6_maxfragpackets &&
		    ip6q.ip6q_prev) {
			ip6stat.ip6s_fragoverflow++;
			/* XXX in6_ifstat_inc(ifp, ifs6_reass_fail) */
			frag6_freef(ip6q.ip6q_prev, &dfq6, &diq6);
		}
	}
	/* re-arm the purge timer if there's work to do */
	frag6_timeout_run = 0;
	frag6_sched_timeout();
	lck_mtx_unlock(&ip6qlock);

	/* free fragments that need to be freed */
	if (!MBUFQ_EMPTY(&dfq6))
		MBUFQ_DRAIN(&dfq6);

	frag6_icmp6_timeex_error(&diq6);

	VERIFY(MBUFQ_EMPTY(&dfq6));
	VERIFY(MBUFQ_EMPTY(&diq6));
}

static void
frag6_sched_timeout(void)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);

	if (!frag6_timeout_run && frag6_nfragpackets > 0) {
		frag6_timeout_run = 1;
		timeout(frag6_timeout, NULL, hz);
	}
}

/*
 * Drain off all datagram fragments.
 */
void
frag6_drain(void)
{
	struct fq6_head dfq6, diq6;

	MBUFQ_INIT(&dfq6);	/* for deferred frees */
	MBUFQ_INIT(&diq6);	/* for deferred ICMP time exceeded errors */

	lck_mtx_lock(&ip6qlock);
	while (ip6q.ip6q_next != &ip6q) {
		ip6stat.ip6s_fragdropped++;
		/* XXX in6_ifstat_inc(ifp, ifs6_reass_fail) */
		frag6_freef(ip6q.ip6q_next, &dfq6, &diq6);
	}
	lck_mtx_unlock(&ip6qlock);

	/* free fragments that need to be freed */
	if (!MBUFQ_EMPTY(&dfq6))
		MBUFQ_DRAIN(&dfq6);

	frag6_icmp6_timeex_error(&diq6);

	VERIFY(MBUFQ_EMPTY(&dfq6));
	VERIFY(MBUFQ_EMPTY(&diq6));
}

static struct ip6q *
ip6q_alloc(int how)
{
	struct mbuf *t;
	struct ip6q *q6;

	/*
	 * See comments in ip6q_updateparams().  Keep the count separate
	 * from frag6_nfragpackets since the latter represents the elements
	 * already in the reassembly queues.
	 */
	if (ip6q_limit > 0 && ip6q_count > ip6q_limit)
		return (NULL);

	t = m_get(how, MT_FTABLE);
	if (t != NULL) {
		atomic_add_32(&ip6q_count, 1);
		q6 = mtod(t, struct ip6q *);
		bzero(q6, sizeof (*q6));
	} else {
		q6 = NULL;
	}
	return (q6);
}

static void
ip6q_free(struct ip6q *q6)
{
	(void) m_free(dtom(q6));
	atomic_add_32(&ip6q_count, -1);
}

static struct ip6asfrag *
ip6af_alloc(int how)
{
	struct mbuf *t;
	struct ip6asfrag *af6;

	/*
	 * See comments in ip6q_updateparams().  Keep the count separate
	 * from frag6_nfrags since the latter represents the elements
	 * already in the reassembly queues.
	 */
	if (ip6af_limit > 0 && ip6af_count > ip6af_limit)
		return (NULL);

	t = m_get(how, MT_FTABLE);
	if (t != NULL) {
		atomic_add_32(&ip6af_count, 1);
		af6 = mtod(t, struct ip6asfrag *);
		bzero(af6, sizeof (*af6));
	} else {
		af6 = NULL;
	}
	return (af6);
}

static void
ip6af_free(struct ip6asfrag *af6)
{
	(void) m_free(dtom(af6));
	atomic_add_32(&ip6af_count, -1);
}

static void
ip6q_updateparams(void)
{
	lck_mtx_assert(&ip6qlock, LCK_MTX_ASSERT_OWNED);
	/*
	 * -1 for unlimited allocation.
	 */
	if (ip6_maxfragpackets < 0)
		ip6q_limit = 0;
	if (ip6_maxfrags < 0)
		ip6af_limit = 0;
	/*
	 * Positive number for specific bound.
	 */
	if (ip6_maxfragpackets > 0)
		ip6q_limit = ip6_maxfragpackets;
	if (ip6_maxfrags > 0)
		ip6af_limit = ip6_maxfrags;
	/*
	 * Zero specifies no further fragment queue allocation -- set the
	 * bound very low, but rely on implementation elsewhere to actually
	 * prevent allocation and reclaim current queues.
	 */
	if (ip6_maxfragpackets == 0)
		ip6q_limit = 1;
	if (ip6_maxfrags == 0)
		ip6af_limit = 1;
	/*
	 * Arm the purge timer if not already and if there's work to do
	 */
	frag6_sched_timeout();
}

static int
sysctl_maxfragpackets SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	lck_mtx_lock(&ip6qlock);
	i = ip6_maxfragpackets;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	/* impose bounds */
	if (i < -1 || i > (nmbclusters / 4)) {
		error = EINVAL;
		goto done;
	}
	ip6_maxfragpackets = i;
	ip6q_updateparams();
done:
	lck_mtx_unlock(&ip6qlock);
	return (error);
}

static int
sysctl_maxfrags SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	lck_mtx_lock(&ip6qlock);
	i = ip6_maxfrags;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	/* impose bounds */
	if (i < -1 || i > (nmbclusters / 4)) {
		error = EINVAL;
		goto done;
	}
	ip6_maxfrags= i;
	ip6q_updateparams();	/* see if we need to arm timer */
done:
	lck_mtx_unlock(&ip6qlock);
	return (error);
}
