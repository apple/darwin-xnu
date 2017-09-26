/*
 * Copyright (c) 2012-2017 Apple Inc. All rights reserved.
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

#ifdef KERNEL
#include <sys/param.h>
#include <machine/endian.h>
#include <sys/mcache.h>
#include <sys/mbuf.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include <mach/boolean.h>
#include <pexpert/pexpert.h>
#define	CKSUM_ERR(fmt, args...)	kprintf(fmt, ## args)
#else /* !KERNEL */
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <strings.h>
#include <mach/boolean.h>
#endif /* !KERNEL */

/* compile time assert */
#ifndef _CASSERT
#define	_CASSERT(x)	_Static_assert(x, "compile-time assertion failed")
#endif /* !_CASSERT */

#ifndef VERIFY
#define	VERIFY(EX) ((void)0)
#endif /* !VERIFY */

#ifndef CKSUM_ERR
#define	CKSUM_ERR(fmt, args...) ((void)0)
#endif /* !CKSUM_ERR */

#define	PREDICT_TRUE(x)		__builtin_expect(!!((long)(x)), 1L)
#define	PREDICT_FALSE(x)	__builtin_expect(!!((long)(x)), 0L)

/* fake mbuf struct used only for calling os_cpu_in_cksum_mbuf() */
struct _mbuf {
	struct _mbuf	*_m_next;
	void		*_m_pad;
	uint8_t		*_m_data;
	int32_t		_m_len;
};

extern uint32_t os_cpu_in_cksum(const void *, uint32_t, uint32_t);
extern uint32_t os_cpu_in_cksum_mbuf(struct _mbuf *, int, int, uint32_t);

uint32_t
os_cpu_in_cksum(const void *data, uint32_t len, uint32_t initial_sum)
{
	/*
	 * If data is 4-bytes aligned, length is multiple of 4-bytes,
	 * and the amount to checksum is small, this would be quicker;
	 * this is suitable for IPv4 header.
	 */
	if (IS_P2ALIGNED(data, sizeof (uint32_t)) &&
	    len <= 64 && (len & 3) == 0) {
		uint8_t *p = __DECONST(uint8_t *, data);
		uint64_t sum = initial_sum;

		if (PREDICT_TRUE(len == 20)) {	/* simple IPv4 header */
			sum += *(uint32_t *)(void *)p;
			sum += *(uint32_t *)(void *)(p + 4);
			sum += *(uint32_t *)(void *)(p + 8);
			sum += *(uint32_t *)(void *)(p + 12);
			sum += *(uint32_t *)(void *)(p + 16);
		} else {
			while (len) {
				sum += *(uint32_t *)(void *)p;
				p += 4;
				len -= 4;
			}
		}

		/* fold 64-bit to 16-bit (deferred carries) */
		sum = (sum >> 32) + (sum & 0xffffffff);	/* 33-bit */
		sum = (sum >> 16) + (sum & 0xffff);	/* 17-bit + carry */
		sum = (sum >> 16) + (sum & 0xffff);	/* 16-bit + carry */
		sum = (sum >> 16) + (sum & 0xffff);	/* final carry */

		return (sum & 0xffff);
	}

	/*
	 * Otherwise, let os_cpu_in_cksum_mbuf() handle it; it only looks
	 * at 3 fields: {next,data,len}, and since it doesn't care about
	 * the authenticity of the mbuf, we use a fake one here.  Make
	 * sure the offsets are as expected.
	 */
#if defined(__LP64__)
	_CASSERT(offsetof(struct _mbuf, _m_next) == 0);
	_CASSERT(offsetof(struct _mbuf, _m_data) == 16);
	_CASSERT(offsetof(struct _mbuf, _m_len) == 24);
#else /* !__LP64__ */
	_CASSERT(offsetof(struct _mbuf, _m_next) == 0);
	_CASSERT(offsetof(struct _mbuf, _m_data) == 8);
	_CASSERT(offsetof(struct _mbuf, _m_len) == 12);
#endif /* !__LP64__ */
#ifdef KERNEL
	_CASSERT(offsetof(struct _mbuf, _m_next) ==
	    offsetof(struct mbuf, m_next));
	_CASSERT(offsetof(struct _mbuf, _m_data) ==
	    offsetof(struct mbuf, m_data));
	_CASSERT(offsetof(struct _mbuf, _m_len) ==
	    offsetof(struct mbuf, m_len));
#endif /* KERNEL */
	struct _mbuf m = {
		._m_next = NULL,
		._m_data = __DECONST(uint8_t *, data),
		._m_len = len,
	};

	return (os_cpu_in_cksum_mbuf(&m, len, 0, initial_sum));
}

#if defined(__i386__) || defined(__x86_64__)

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 *
 * A discussion of different implementation techniques can be found in
 * RFC 1071.
 *
 * The default implementation for 32-bit architectures is using
 * a 32-bit accumulator and operating on 16-bit operands.
 *
 * The default implementation for 64-bit architectures is using
 * a 64-bit accumulator and operating on 32-bit operands.
 *
 * Both versions are unrolled to handle 32 Byte / 64 Byte fragments as core
 * of the inner loop. After each iteration of the inner loop, a partial
 * reduction is done to avoid carry in long packets.
 */

#if !defined(__LP64__)
/* 32-bit version */
uint32_t
os_cpu_in_cksum_mbuf(struct _mbuf *m, int len, int off, uint32_t initial_sum)
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
		if (PREDICT_FALSE(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->_m_len;
		if (mlen > off) {
			mlen -= off;
			data = m->_m_data + off;
			goto post_initial_offset;
		}
		off -= mlen;
		if (len == 0)
			break;
		m = m->_m_next;
	}

	for (; len > 0; m = m->_m_next) {
		if (PREDICT_FALSE(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->_m_len;
		data = m->_m_data;
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
#else
			partial = *data;
#endif
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
			if (PREDICT_FALSE(partial & 0xc0000000)) {
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
#else
			partial += *data << 8;
#endif
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
os_cpu_in_cksum_mbuf(struct _mbuf *m, int len, int off, uint32_t initial_sum)
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
		if (PREDICT_FALSE(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->_m_len;
		if (mlen > off) {
			mlen -= off;
			data = m->_m_data + off;
			goto post_initial_offset;
		}
		off -= mlen;
		if (len == 0)
			break;
		m = m->_m_next;
	}

	for (; len > 0; m = m->_m_next) {
		if (PREDICT_FALSE(m == NULL)) {
			CKSUM_ERR("%s: out of data\n", __func__);
			return ((uint32_t)-1);
		}
		mlen = m->_m_len;
		data = m->_m_data;
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
#else
			partial = *data;
#endif
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
			if (PREDICT_FALSE(partial & (3ULL << 62))) {
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
#else
			partial += *data << 8;
#endif
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

#endif /* __i386__ || __x86_64__ */
