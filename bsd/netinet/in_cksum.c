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

#include <sys/param.h>
#include <machine/endian.h>
#include <sys/mbuf.h>
#include <kern/debug.h>
#include <net/dlil.h>
#include <netinet/in.h>
#define	_IP_VHL
#include <netinet/ip.h>
#include <netinet/ip_var.h>

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */
#define REDUCE16 {							  \
	q_util.q = sum;							  \
	l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
	sum = l_util.s[0] + l_util.s[1];				  \
	ADDCARRY(sum);							  \
}

union l_util {
        uint16_t s[2];
        uint32_t l;
};

union q_util {
        uint16_t s[4];
        uint32_t l[2];
        uint64_t q;
};

extern uint32_t os_cpu_in_cksum(const void *, uint32_t, uint32_t);

/*
 * Perform 16-bit 1's complement sum on a contiguous span.
 */
uint16_t
b_sum16(const void *buf, int len)
{
	return (os_cpu_in_cksum(buf, len, 0));
}

uint16_t inet_cksum_simple(struct mbuf *, int);
/*
 * For the exported _in_cksum symbol in BSDKernel symbol set.
 */
uint16_t
inet_cksum_simple(struct mbuf *m, int len)
{
	return (inet_cksum(m, 0, 0, len));
}

uint16_t
in_addword(uint16_t a, uint16_t b)
{
	uint64_t sum = a + b;

	ADDCARRY(sum);
	return (sum);
}

uint16_t
in_pseudo(uint32_t a, uint32_t b, uint32_t c)
{
        uint64_t sum;
        union q_util q_util;
        union l_util l_util;

        sum = (uint64_t)a + b + c;
        REDUCE16;
        return (sum);
}

uint16_t
in_pseudo64(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t sum;
	union q_util q_util;
	union l_util l_util;

	sum = a + b + c;
	REDUCE16;
	return (sum);
}

/*
 * May be used on IP header with options.
 */
uint16_t
in_cksum_hdr_opt(const struct ip *ip)
{
	return (~b_sum16(ip, (IP_VHL_HL(ip->ip_vhl) << 2)) & 0xffff);
}

/*
 * A wrapper around the simple in_cksum_hdr() and the more complicated
 * inet_cksum(); the former is chosen if the IP header is simple,
 * contiguous and 32-bit aligned.  Also does some stats accounting.
 */
uint16_t
ip_cksum_hdr_dir(struct mbuf *m, uint32_t hlen, int out)
{
	struct ip *ip = mtod(m, struct ip *);

	if (out) {
		ipstat.ips_snd_swcsum++;
		ipstat.ips_snd_swcsum_bytes += hlen;
	} else {
		ipstat.ips_rcv_swcsum++;
		ipstat.ips_rcv_swcsum_bytes += hlen;
	}

	if (hlen == sizeof (*ip) &&
	    m->m_len >= sizeof (*ip) && IP_HDR_ALIGNED_P(ip))
		return (in_cksum_hdr(ip));

	return (inet_cksum(m, 0, 0, hlen));
}

uint16_t
ip_cksum_hdr_dir_buffer(const void *buffer, uint32_t hlen, uint32_t len,
    int out)
{
	const struct ip *ip = buffer;

	if (out) {
		ipstat.ips_snd_swcsum++;
		ipstat.ips_snd_swcsum_bytes += hlen;
	} else {
		ipstat.ips_rcv_swcsum++;
		ipstat.ips_rcv_swcsum_bytes += hlen;
	}

	if (hlen == sizeof (*ip) &&
	    len >= sizeof (*ip) && IP_HDR_ALIGNED_P(ip))
		return (in_cksum_hdr(ip));

	return (inet_cksum_buffer(buffer, 0, 0, hlen));
}

/*
 * m MUST contain at least an IP header, if nxt is specified;
 * nxt is the upper layer protocol number;
 * off is an offset where TCP/UDP/ICMP header starts;
 * len is a total length of a transport segment (e.g. TCP header + TCP payload)
 */
uint16_t
inet_cksum(struct mbuf *m, uint32_t nxt, uint32_t off, uint32_t len)
{
	uint32_t sum;

	sum = m_sum16(m, off, len);

	/* include pseudo header checksum? */
	if (nxt != 0) {
		struct ip *ip;
		unsigned char buf[sizeof ((*ip))] __attribute__((aligned(8)));
		uint32_t mlen;

		/*
		 * Sanity check
		 *
		 * Use m_length2() instead of m_length(), as we cannot rely on
		 * the caller setting m_pkthdr.len correctly, if the mbuf is
		 * a M_PKTHDR one.
		 */
		if ((mlen = m_length2(m, NULL)) < sizeof (*ip)) {
			panic("%s: mbuf %p too short (%d) for IPv4 header",
			    __func__, m, mlen);
			/* NOTREACHED */
		}

		/*
		 * In case the IP header is not contiguous, or not 32-bit
		 * aligned, copy it to a local buffer.  Note here that we
		 * expect the data pointer to point to the IP header.
		 */
		if ((sizeof (*ip) > m->m_len) ||
		    !IP_HDR_ALIGNED_P(mtod(m, caddr_t))) {
			m_copydata(m, 0, sizeof (*ip), (caddr_t)buf);
			ip = (struct ip *)(void *)buf;
		} else {
			ip = (struct ip *)(void *)(m->m_data);
		}

		/* add pseudo header checksum */
		sum += in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    htonl(len + nxt));

		/* fold in carry bits */
		ADDCARRY(sum);
	}

	return (~sum & 0xffff);
}

/*
 * buffer MUST contain at least an IP header, if nxt is specified;
 * nxt is the upper layer protocol number;
 * off is an offset where TCP/UDP/ICMP header starts;
 * len is a total length of a transport segment (e.g. TCP header + TCP payload)
 */
uint16_t
inet_cksum_buffer(const void *buffer, uint32_t nxt, uint32_t off,
    uint32_t len)
{
	uint32_t sum;

	if (off >= len)
		panic("%s: off (%d) >= len (%d)", __func__, off, len);

	sum = b_sum16(&((const uint8_t *)buffer)[off], len);

	/* include pseudo header checksum? */
	if (nxt != 0) {
		const struct ip *ip;
		unsigned char buf[sizeof ((*ip))] __attribute__((aligned(8)));

		/*
		 * In case the IP header is not contiguous, or not 32-bit
		 * aligned, copy it to a local buffer.  Note here that we
		 * expect the data pointer to point to the IP header.
		 */
		if (!IP_HDR_ALIGNED_P(buffer)) {
			memcpy(buf, buffer, sizeof (*ip));
			ip = (const struct ip *)(const void *)buf;
		} else {
			ip = (const struct ip *)buffer;
		}

		/* add pseudo header checksum */
		sum += in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    htonl(len + nxt));

		/* fold in carry bits */
		ADDCARRY(sum);
	}

	return (~sum & 0xffff);
}

#if DEBUG || DEVELOPMENT
#include <pexpert/pexpert.h>

#define	CKSUM_ERR kprintf

/*
 * The following routines implement the portable, reference implementation
 * of os_cpu_in_cksum_mbuf().  This is currently used only for validating
 * the correctness of the platform-specific implementation, at boot time
 * in dlil_verify_sum16().  It returns the 32-bit accumulator without doing
 * a 1's complement on it.
 */
#if !defined(__LP64__)
/* 32-bit version */
uint32_t
in_cksum_mbuf_ref(struct mbuf *m, int len, int off, uint32_t initial_sum)
{
	int mlen;
	uint32_t sum, partial;
	unsigned int final_acc;
	uint8_t *data;
	boolean_t needs_swap, started_on_odd;

	VERIFY(len >= 0);
	VERIFY(off >= 0);

	needs_swap = FALSE;
	started_on_odd = FALSE;
	sum = (initial_sum >> 16) + (initial_sum & 0xffff);

	for (;;) {
		if (__improbable(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->m_len;
		if (mlen > off) {
			mlen -= off;
			data = mtod(m, uint8_t *) + off;
			goto post_initial_offset;
		}
		off -= mlen;
		if (len == 0)
			break;
		m = m->m_next;
	}

	for (; len > 0; m = m->m_next) {
		if (__improbable(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->m_len;
		data = mtod(m, uint8_t *);
post_initial_offset:
		if (mlen == 0)
			continue;
		if (mlen > len)
			mlen = len;
		len -= mlen;

		partial = 0;
		if ((uintptr_t)data & 1) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = *data << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial = *data;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			++data;
			--mlen;
		}
		needs_swap = started_on_odd;
		while (mlen >= 32) {
			__builtin_prefetch(data + 32);
			partial += *(uint16_t *)(void *)data;
			partial += *(uint16_t *)(void *)(data + 2);
			partial += *(uint16_t *)(void *)(data + 4);
			partial += *(uint16_t *)(void *)(data + 6);
			partial += *(uint16_t *)(void *)(data + 8);
			partial += *(uint16_t *)(void *)(data + 10);
			partial += *(uint16_t *)(void *)(data + 12);
			partial += *(uint16_t *)(void *)(data + 14);
			partial += *(uint16_t *)(void *)(data + 16);
			partial += *(uint16_t *)(void *)(data + 18);
			partial += *(uint16_t *)(void *)(data + 20);
			partial += *(uint16_t *)(void *)(data + 22);
			partial += *(uint16_t *)(void *)(data + 24);
			partial += *(uint16_t *)(void *)(data + 26);
			partial += *(uint16_t *)(void *)(data + 28);
			partial += *(uint16_t *)(void *)(data + 30);
			data += 32;
			mlen -= 32;
			if (__improbable(partial & 0xc0000000)) {
				if (needs_swap)
					partial = (partial << 8) +
					    (partial >> 24);
				sum += (partial >> 16);
				sum += (partial & 0xffff);
				partial = 0;
			}
		}
		if (mlen & 16) {
			partial += *(uint16_t *)(void *)data;
			partial += *(uint16_t *)(void *)(data + 2);
			partial += *(uint16_t *)(void *)(data + 4);
			partial += *(uint16_t *)(void *)(data + 6);
			partial += *(uint16_t *)(void *)(data + 8);
			partial += *(uint16_t *)(void *)(data + 10);
			partial += *(uint16_t *)(void *)(data + 12);
			partial += *(uint16_t *)(void *)(data + 14);
			data += 16;
			mlen -= 16;
		}
		/*
		 * mlen is not updated below as the remaining tests
		 * are using bit masks, which are not affected.
		 */
		if (mlen & 8) {
			partial += *(uint16_t *)(void *)data;
			partial += *(uint16_t *)(void *)(data + 2);
			partial += *(uint16_t *)(void *)(data + 4);
			partial += *(uint16_t *)(void *)(data + 6);
			data += 8;
		}
		if (mlen & 4) {
			partial += *(uint16_t *)(void *)data;
			partial += *(uint16_t *)(void *)(data + 2);
			data += 4;
		}
		if (mlen & 2) {
			partial += *(uint16_t *)(void *)data;
			data += 2;
		}
		if (mlen & 1) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += *data;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial += *data << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			started_on_odd = !started_on_odd;
		}

		if (needs_swap)
			partial = (partial << 8) + (partial >> 24);
		sum += (partial >> 16) + (partial & 0xffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 16) + (sum & 0xffff);
	}
	final_acc = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	return (final_acc & 0xffff);
}

#else /* __LP64__ */
/* 64-bit version */
uint32_t
in_cksum_mbuf_ref(struct mbuf *m, int len, int off, uint32_t initial_sum)
{
	int mlen;
	uint64_t sum, partial;
	unsigned int final_acc;
	uint8_t *data;
	boolean_t needs_swap, started_on_odd;

	VERIFY(len >= 0);
	VERIFY(off >= 0);

	needs_swap = FALSE;
	started_on_odd = FALSE;
	sum = initial_sum;

	for (;;) {
		if (__improbable(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->m_len;
		if (mlen > off) {
			mlen -= off;
			data = mtod(m, uint8_t *) + off;
			goto post_initial_offset;
		}
		off -= mlen;
		if (len == 0)
			break;
		m = m->m_next;
	}

	for (; len > 0; m = m->m_next) {
		if (__improbable(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->m_len;
		data = mtod(m, uint8_t *);
post_initial_offset:
		if (mlen == 0)
			continue;
		if (mlen > len)
			mlen = len;
		len -= mlen;

		partial = 0;
		if ((uintptr_t)data & 1) {
			/* Align on word boundary */
			started_on_odd = !started_on_odd;
#if BYTE_ORDER == LITTLE_ENDIAN
			partial = *data << 8;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial = *data;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			++data;
			--mlen;
		}
		needs_swap = started_on_odd;
		if ((uintptr_t)data & 2) {
			if (mlen < 2)
				goto trailing_bytes;
			partial += *(uint16_t *)(void *)data;
			data += 2;
			mlen -= 2;
		}
		while (mlen >= 64) {
			__builtin_prefetch(data + 32);
			__builtin_prefetch(data + 64);
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			partial += *(uint32_t *)(void *)(data + 16);
			partial += *(uint32_t *)(void *)(data + 20);
			partial += *(uint32_t *)(void *)(data + 24);
			partial += *(uint32_t *)(void *)(data + 28);
			partial += *(uint32_t *)(void *)(data + 32);
			partial += *(uint32_t *)(void *)(data + 36);
			partial += *(uint32_t *)(void *)(data + 40);
			partial += *(uint32_t *)(void *)(data + 44);
			partial += *(uint32_t *)(void *)(data + 48);
			partial += *(uint32_t *)(void *)(data + 52);
			partial += *(uint32_t *)(void *)(data + 56);
			partial += *(uint32_t *)(void *)(data + 60);
			data += 64;
			mlen -= 64;
			if (__improbable(partial & (3ULL << 62))) {
				if (needs_swap)
					partial = (partial << 8) +
					    (partial >> 56);
				sum += (partial >> 32);
				sum += (partial & 0xffffffff);
				partial = 0;
			}
		}
		/*
		 * mlen is not updated below as the remaining tests
		 * are using bit masks, which are not affected.
		 */
		if (mlen & 32) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			partial += *(uint32_t *)(void *)(data + 16);
			partial += *(uint32_t *)(void *)(data + 20);
			partial += *(uint32_t *)(void *)(data + 24);
			partial += *(uint32_t *)(void *)(data + 28);
			data += 32;
		}
		if (mlen & 16) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			partial += *(uint32_t *)(void *)(data + 8);
			partial += *(uint32_t *)(void *)(data + 12);
			data += 16;
		}
		if (mlen & 8) {
			partial += *(uint32_t *)(void *)data;
			partial += *(uint32_t *)(void *)(data + 4);
			data += 8;
		}
		if (mlen & 4) {
			partial += *(uint32_t *)(void *)data;
			data += 4;
		}
		if (mlen & 2) {
			partial += *(uint16_t *)(void *)data;
			data += 2;
		}
trailing_bytes:
		if (mlen & 1) {
#if BYTE_ORDER == LITTLE_ENDIAN
			partial += *data;
#else /* BYTE_ORDER != LITTLE_ENDIAN */
			partial += *data << 8;
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
			started_on_odd = !started_on_odd;
		}

		if (needs_swap)
			partial = (partial << 8) + (partial >> 56);
		sum += (partial >> 32) + (partial & 0xffffffff);
		/*
		 * Reduce sum to allow potential byte swap
		 * in the next iteration without carry.
		 */
		sum = (sum >> 32) + (sum & 0xffffffff);
	}
	final_acc = (sum >> 48) + ((sum >> 32) & 0xffff) +
	    ((sum >> 16) & 0xffff) + (sum & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
	return (final_acc & 0xffff);
}
#endif /* __LP64 */
#endif /* DEBUG || DEVELOPMENT */
