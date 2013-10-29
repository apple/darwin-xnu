/*
 * Copyright (c) 2007-2011 Apple Inc. All rights reserved.
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

/*
 * Copyright (c) 1991-1997 Regents of the University of California.
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
 *      This product includes software developed by the Network Research
 *      Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/kernel_types.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/net_osdep.h>
#include <net/classq/classq.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <libkern/libkern.h>

#if PF_ECN
/*
 * read and write diffserv field in IPv4 or IPv6 header
 */
u_int8_t
read_dsfield(struct mbuf *m, struct pf_mtag *t)
{
	struct mbuf *m0;
	u_int8_t ds_field = 0;

	if (t->pftag_hdr == NULL ||
	    !(t->pftag_flags & (PF_TAG_HDR_INET|PF_TAG_HDR_INET6)))
		return ((u_int8_t)0);

	/* verify that hdr is within the mbuf data */
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		if (((caddr_t)t->pftag_hdr >= m0->m_data) &&
		    ((caddr_t)t->pftag_hdr < m0->m_data + m0->m_len))
			break;
	if (m0 == NULL) {
		/* ick, tag info is stale */
		printf("%s: can't locate header!\n", __func__);
		return ((u_int8_t)0);
	}

	if (t->pftag_flags & PF_TAG_HDR_INET) {
		struct ip *ip = (struct ip *)(void *)t->pftag_hdr;

		if (((uintptr_t)ip + sizeof (*ip)) >
		    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
			return (0);		/* out of bounds */

		if (ip->ip_v != 4)
			return ((u_int8_t)0);	/* version mismatch! */
		ds_field = ip->ip_tos;
	}
#if INET6
	else if (t->pftag_flags & PF_TAG_HDR_INET6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(void *)t->pftag_hdr;
		u_int32_t flowlabel;

		if (((uintptr_t)ip6 + sizeof (*ip6)) >
		    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
			return (0);		/* out of bounds */

		flowlabel = ntohl(ip6->ip6_flow);
		if ((flowlabel >> 28) != 6)
			return ((u_int8_t)0);	/* version mismatch! */
		ds_field = (flowlabel >> 20) & 0xff;
	}
#endif
	return (ds_field);
}

void
write_dsfield(struct mbuf *m, struct pf_mtag *t, u_int8_t dsfield)
{
	struct mbuf *m0;

	if (t->pftag_hdr == NULL ||
	    !(t->pftag_flags & (PF_TAG_HDR_INET|PF_TAG_HDR_INET6)))
		return;

	/* verify that hdr is within the mbuf data */
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		if (((caddr_t)t->pftag_hdr >= m0->m_data) &&
		    ((caddr_t)t->pftag_hdr < m0->m_data + m0->m_len))
			break;
	if (m0 == NULL) {
		/* ick, tag info is stale */
		printf("%s: can't locate header!\n", __func__);
		return;
	}

	if (t->pftag_flags & PF_TAG_HDR_INET) {
		struct ip *ip = (struct ip *)(void *)t->pftag_hdr;
		u_int8_t old;
		int32_t sum;

		if (((uintptr_t)ip + sizeof (*ip)) >
		    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
			return;		/* out of bounds */

		if (ip->ip_v != 4)
			return;		/* version mismatch! */
		old = ip->ip_tos;
		dsfield |= old & 3;	/* leave CU bits */
		if (old == dsfield)
			return;
		ip->ip_tos = dsfield;
		/*
		 * update checksum (from RFC1624)
		 *	   HC' = ~(~HC + ~m + m')
		 */
		sum = ~ntohs(ip->ip_sum) & 0xffff;
		sum += 0xff00 + (~old & 0xff) + dsfield;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);  /* add carry */

		ip->ip_sum = htons(~sum & 0xffff);
	}
#if INET6
	else if (t->pftag_flags & PF_TAG_HDR_INET6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)t->pftag_hdr;
		u_int32_t flowlabel;

		if (((uintptr_t)ip6 + sizeof (*ip6)) >
		    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
			return;		/* out of bounds */

		flowlabel = ntohl(ip6->ip6_flow);
		if ((flowlabel >> 28) != 6)
			return;		/* version mismatch! */
		flowlabel = (flowlabel & 0xf03fffff) | (dsfield << 20);
		ip6->ip6_flow = htonl(flowlabel);
	}
#endif
}

/*
 * try to mark CE bit to the packet.
 *    returns 1 if successfully marked, 0 otherwise.
 */
int
mark_ecn(struct mbuf *m, struct pf_mtag *t, int flags)
{
	struct mbuf	*m0;
	void		*hdr;
	int		af;

	if ((hdr = t->pftag_hdr) == NULL ||
	    !(t->pftag_flags & (PF_TAG_HDR_INET|PF_TAG_HDR_INET6)))
		return (0);

	/* verify that hdr is within the mbuf data */
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		if (((caddr_t)hdr >= m0->m_data) &&
		    ((caddr_t)hdr < m0->m_data + m0->m_len))
			break;
	if (m0 == NULL) {
		/* ick, tag info is stale */
		printf("%s: can't locate header!\n", __func__);
		return (0);
	}

	if (t->pftag_flags & PF_TAG_HDR_INET)
		af = AF_INET;
	else if (t->pftag_flags & PF_TAG_HDR_INET6)
		af = AF_INET6;
	else
		af = AF_UNSPEC;

	switch (af) {
	case AF_INET:
		if (flags & CLASSQF_ECN4) {	/* REDF_ECN4 == BLUEF_ECN4 */
			struct ip *ip = hdr;
			u_int8_t otos;
			int sum;

			if (((uintptr_t)ip + sizeof (*ip)) >
			    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
				return (0);	/* out of bounds */

			if (ip->ip_v != 4)
				return (0);	/* version mismatch! */
			if ((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_NOTECT)
				return (0);	/* not-ECT */
			if ((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE)
				return (1);	/* already marked */

			/*
			 * ecn-capable but not marked,
			 * mark CE and update checksum
			 */
			otos = ip->ip_tos;
			ip->ip_tos |= IPTOS_ECN_CE;
			/*
			 * update checksum (from RFC1624)
			 *	   HC' = ~(~HC + ~m + m')
			 */
			sum = ~ntohs(ip->ip_sum) & 0xffff;
			sum += (~otos & 0xffff) + ip->ip_tos;
			sum = (sum >> 16) + (sum & 0xffff);
			sum += (sum >> 16);  /* add carry */
			ip->ip_sum = htons(~sum & 0xffff);
			return (1);
		}
		break;
#if INET6
	case AF_INET6:
		if (flags & CLASSQF_ECN6) {	/* REDF_ECN6 == BLUEF_ECN6 */
			struct ip6_hdr *ip6 = hdr;
			u_int32_t flowlabel;

			if (((uintptr_t)ip6 + sizeof (*ip6)) >
			    ((uintptr_t)mbuf_datastart(m0) + mbuf_maxlen(m0)))
				return (0);	/* out of bounds */

			flowlabel = ntohl(ip6->ip6_flow);
			if ((flowlabel >> 28) != 6)
				return (0);	/* version mismatch! */
			if ((flowlabel & (IPTOS_ECN_MASK << 20)) ==
			    (IPTOS_ECN_NOTECT << 20))
				return (0);	/* not-ECT */
			if ((flowlabel & (IPTOS_ECN_MASK << 20)) ==
			    (IPTOS_ECN_CE << 20))
				return (1);	/* already marked */
			/*
			 * ecn-capable but not marked,  mark CE
			 */
			flowlabel |= (IPTOS_ECN_CE << 20);
			ip6->ip6_flow = htonl(flowlabel);
			return (1);
		}
		break;
#endif  /* INET6 */
	}

	/* not marked */
	return (0);
}
#endif /* PF_ECN */
