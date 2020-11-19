/*
 * Copyright (c) 2009-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 1988, 1992, 1993
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
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */

/*-
 * Copyright (c) 2008 Joerg Sonnenberger <joerg@NetBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <machine/endian.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <kern/debug.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */

/*
 * Compute IPv6 pseudo-header checksum; assumes 16-bit aligned pointers.
 */
uint16_t
in6_pseudo(const struct in6_addr *src, const struct in6_addr *dst, uint32_t x)
{
	uint32_t sum = 0;
	const uint16_t *w;

	/*
	 * IPv6 source address
	 */
	w = (const uint16_t *)src;
	sum += w[0];
	if (!IN6_IS_SCOPE_EMBED(src)) {
		sum += w[1];
	}
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	/*
	 * IPv6 destination address
	 */
	w = (const uint16_t *)dst;
	sum += w[0];
	if (!IN6_IS_SCOPE_EMBED(dst)) {
		sum += w[1];
	}
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	/*
	 * Caller-supplied value; 'x' could be one of:
	 *
	 *	htonl(proto + length), or
	 *	htonl(proto + length + sum)
	 **/
	sum += x;

	/* fold in carry bits */
	ADDCARRY(sum);

	return (uint16_t)sum;
}

/*
 * m MUST contain at least an IPv6 header, if nxt is specified;
 * nxt is the upper layer protocol number;
 * off is an offset where TCP/UDP/ICMP6 header starts;
 * len is a total length of a transport segment (e.g. TCP header + TCP payload)
 */
u_int16_t
inet6_cksum(struct mbuf *m, uint32_t nxt, uint32_t off, uint32_t len)
{
	uint32_t sum;

	sum = m_sum16(m, off, len);

	if (nxt != 0) {
		struct ip6_hdr *ip6;
		unsigned char buf[sizeof(*ip6)] __attribute__((aligned(8)));
		uint32_t mlen;

		/*
		 * Sanity check
		 *
		 * Use m_length2() instead of m_length(), as we cannot rely on
		 * the caller setting m_pkthdr.len correctly, if the mbuf is
		 * a M_PKTHDR one.
		 */
		if ((mlen = m_length2(m, NULL)) < sizeof(*ip6)) {
			panic("%s: mbuf %p pkt too short (%d) for IPv6 header",
			    __func__, m, mlen);
			/* NOTREACHED */
		}

		/*
		 * In case the IPv6 header is not contiguous, or not 32-bit
		 * aligned, copy it to a local buffer.  Note here that we
		 * expect the data pointer to point to the IPv6 header.
		 */
		if ((sizeof(*ip6) > m->m_len) ||
		    !IP6_HDR_ALIGNED_P(mtod(m, caddr_t))) {
			m_copydata(m, 0, sizeof(*ip6), (caddr_t)buf);
			ip6 = (struct ip6_hdr *)(void *)buf;
		} else {
			ip6 = (struct ip6_hdr *)(void *)(m->m_data);
		}

		/* add pseudo header checksum */
		sum += in6_pseudo(&ip6->ip6_src, &ip6->ip6_dst,
		    htonl(nxt + len));

		/* fold in carry bits */
		ADDCARRY(sum);
	}

	return ~sum & 0xffff;
}

/*
 * buffer MUST contain at least an IPv6 header, if nxt is specified;
 * nxt is the upper layer protocol number;
 * off is an offset where TCP/UDP/ICMP6 header starts;
 * len is a total length of a transport segment (e.g. TCP header + TCP payload)
 */
u_int16_t
inet6_cksum_buffer(const uint8_t *buffer, uint32_t nxt, uint32_t off,
    uint32_t len)
{
	uint32_t sum;

	if (off >= len) {
		panic("%s: off (%d) >= len (%d)", __func__, off, len);
	}

	sum = b_sum16(&((const uint8_t *)buffer)[off], len);

	if (nxt != 0) {
		const struct ip6_hdr *ip6;
		unsigned char buf[sizeof(*ip6)] __attribute__((aligned(8)));

		/*
		 * In case the IPv6 header is not contiguous, or not 32-bit
		 * aligned, copy it to a local buffer.  Note here that we
		 * expect the data pointer to point to the IPv6 header.
		 */
		if (!IP6_HDR_ALIGNED_P(buffer)) {
			memcpy(buf, buffer, sizeof(*ip6));
			ip6 = (const struct ip6_hdr *)(const void *)buf;
		} else {
			ip6 = (const struct ip6_hdr *)buffer;
		}

		/* add pseudo header checksum */
		sum += in6_pseudo(&ip6->ip6_src, &ip6->ip6_dst,
		    htonl(nxt + len));

		/* fold in carry bits */
		ADDCARRY(sum);
	}

	return ~sum & 0xffff;
}
