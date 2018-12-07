/*
 * Copyright (c) 2012-2018 Apple Inc. All rights reserved.
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
 * This assembly was previously cloned from ../arm/cpu_in_cksum.s (__arm__)
 * with __arm64__ tagged ARM64_TODO .  This code revision is optimized based
 * on the 64-bit part in netinet/cpu_in_cksum.c
 *
 * cclee - CoreOS - Vector & Numerics. 06/20/2012.
 */

#ifdef KERNEL
#define	CKSUM_ERR _kprintf
#else
#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#define	CKSUM_ERR _fprintf_stderr
#endif /* !KERNEL */

/*
 * XXX: adi@apple.com:
 *
 * Ugly, but we have little choice, since relying on genassym and <assym.s>
 * is not possible unless this code lives in osfmk.  Note also that this
 * routine expects "mbuf-like" argument, and it does not expect the mbuf to be
 * authentic; it only cares about 3 fields.
 */
#if defined(__LP64__)
#define	M_NEXT	0
#define	M_DATA	16	// 8-byte address, would be aligned to 8-byte boundary
#define	M_LEN	24
#else
#define	M_NEXT	0
#define	M_DATA	8
#define	M_LEN	12
#endif

	.globl	_os_cpu_in_cksum_mbuf
	.text
	.align	4
_os_cpu_in_cksum_mbuf:


/*
 * 64-bit version.
 *
 * This function returns the partial 16-bit checksum accumulated in
 * a 32-bit variable (withouth 1's complement); caller is responsible
 * for folding the 32-bit sum into 16-bit and performinng the 1's
 * complement if applicable
 */

/* 
 * uint32_t
 * os_cpu_in_cksum_mbuf(struct mbuf *m, int len, int off, uint32_t initial_sum)
 * {
 * 	int mlen;
 * 	uint64_t sum, partial;
 * 	unsigned int final_acc;
 * 	uint8_t *data;
 * 	boolean_t needs_swap, started_on_odd;
 *
 * 	VERIFY(len >= 0);
 * 	VERIFY(off >= 0);
 *
 * 	needs_swap = FALSE;
 * 	started_on_odd = FALSE;
 * 	sum = initial_sum;
 */

	#define	m		x0
	#define	len		x1
	#define	off		x2
	#define	sum		x3
	#define	needs_swap	x4
	#define	started_on_odd	x5
	#define	mlen			x6
	#define	Wmlen			w6
	#define t       x7
	#define	data	x8
#if defined(__LP64__)
	#define ptr_m		x0
	#define ptr_data	x8
#else
	#define ptr_m		w0
	#define ptr_data	w8
#endif


	mov	needs_swap, #0		// needs_swap = FALSE;
	mov	started_on_odd, #0	// started_on_odd = FALSE;
	mov	w3, w3			// clear higher half


/*
 *	for (;;) {
 *		if (PREDICT_FALSE(m == NULL)) {
 *			CKSUM_ERR("%s: out of data\n", __func__);
 *			return (-1);
 *		}
 *		mlen = m->m_len;
 *		if (mlen > off) {
 *			mlen -= off;
 *			data = mtod(m, uint8_t *) + off;
 *			goto post_initial_offset;
 *		}
 *		off -= mlen;
 *		if (len == 0)
 *			break;
 *		m = m->m_next;
 *	}
 */

0:
	cbz	m, Lin_cksum_whoops	// if (m == NULL) return -1;
	ldr	Wmlen, [m, #M_LEN]	// mlen = m->m_len;
	cmp	mlen, off
	b.le	1f
	ldr	ptr_data, [m, #M_DATA]	// mtod(m, uint8_t *)
	sub	mlen, mlen, off		// mlen -= off;
	add	data, data, off		// data = mtod(m, uint8_t *) + off;
	b	L_post_initial_offset
1:
	sub	off, off, mlen
	cbnz	len, 2f
	mov	x0, x3
	ret	lr
2:
	ldr	ptr_m, [m, #M_NEXT]
	b	0b

L_loop:	// for (; len > 0; m = m->m_next) {
/*
 *		if (PREDICT_FALSE(m == NULL)) {
 *			CKSUM_ERR("%s: out of data\n", __func__);
 *			return (-1);
 *		}
 *		mlen = m->m_len;
 *		data = mtod(m, uint8_t *);
 */
	cbz	m, Lin_cksum_whoops	// if (m == NULL) return -1;
	ldr	Wmlen, [m, #M_LEN]	// mlen = m->m_len;
	ldr	ptr_data, [m, #M_DATA]	// mtod(m, uint8_t *)

L_post_initial_offset:
/*
 *		if (mlen == 0) continue;
 *		if (mlen > len) mlen = len;
 *		len -= mlen;
 */

	cbz	mlen, L_continue
	cmp	mlen, len
	csel	mlen, mlen, len, le
	sub	len, len, mlen

/*
 *		partial = 0;
 *		if ((uintptr_t)data & 1) {
 *			started_on_odd = !started_on_odd;
 *			partial = *data << 8;
 *			++data;
 *			--mlen;
 *		}
 *		needs_swap = started_on_odd;
 */

	tst	data, #1
	mov	x7, #0
	mov	x10, #0
	b.eq	1f
	ldrb	w7, [data], #1
	eor	started_on_odd, started_on_odd, #1
	sub	mlen, mlen, #1
	lsl	w7, w7, #8
1:


/*
 *		if ((uintptr_t)data & 2) {
 *			if (mlen < 2)
 *				goto trailing_bytes;
 *			partial += *(uint16_t *)(void *)data;
 *			data += 2;
 *			mlen -= 2;
 *		}
 */
	tst	data, #2
	mov	needs_swap, started_on_odd
	b.eq	1f
	cmp	mlen, #2
	b.lt	L_trailing_bytes
	ldrh	w9, [data], #2
	sub	mlen, mlen, #2
	add	w7, w7, w9
1:

/*
 *		while (mlen >= 64) {
 *			__builtin_prefetch(data + 32);
 *			__builtin_prefetch(data + 64);
 *			partial += *(uint32_t *)(void *)data;
 *			partial += *(uint32_t *)(void *)(data + 4);
 *			partial += *(uint32_t *)(void *)(data + 8);
 *			partial += *(uint32_t *)(void *)(data + 12);
 *			partial += *(uint32_t *)(void *)(data + 16);
 *			partial += *(uint32_t *)(void *)(data + 20);
 *			partial += *(uint32_t *)(void *)(data + 24);
 *			partial += *(uint32_t *)(void *)(data + 28);
 *			partial += *(uint32_t *)(void *)(data + 32);
 *			partial += *(uint32_t *)(void *)(data + 36);
 *			partial += *(uint32_t *)(void *)(data + 40);
 *			partial += *(uint32_t *)(void *)(data + 44);
 *			partial += *(uint32_t *)(void *)(data + 48);
 *			partial += *(uint32_t *)(void *)(data + 52);
 *			partial += *(uint32_t *)(void *)(data + 56);
 *			partial += *(uint32_t *)(void *)(data + 60);
 *			data += 64;
 *			mlen -= 64;
 *		//	if (PREDICT_FALSE(partial & (3ULL << 62))) {
 *		//		if (needs_swap)
 *		//			partial = (partial << 8) +
 *		//			    (partial >> 56);
 *		//		sum += (partial >> 32);
 *		//		sum += (partial & 0xffffffff);
 *		//		partial = 0;
 *		//	}
 *		}
*/

	// pre-decrement mlen by 64, and if < 64 bytes, try 32 bytes next
	subs	mlen, mlen, #64
	b.lt	L32_bytes

	// save used vector registers
	sub	sp, sp, #8*16
	mov	x11, sp
	st1.4s	{v0, v1, v2, v3}, [x11], #4*16 
	st1.4s	{v4, v5, v6, v7}, [x11], #4*16 

	// spread partial into 8 8-byte registers in v0-v3
	fmov	s3, w7
	eor.16b	v0, v0, v0
	eor.16b	v1, v1, v1
	eor.16b	v2, v2, v2

	// load the 1st 64 bytes (16 32-bit words)
	ld1.4s	{v4,v5,v6,v7},[data],#64

	// branch to finish off if mlen<64
	subs	mlen, mlen, #64
	b.lt	L64_finishup

	/*
	 * loop for loading and accumulating 16 32-bit words into
	 * 8 8-byte accumulators per iteration.
	 */
L64_loop:
	subs        mlen, mlen, #64             // mlen -= 64

	uadalp.2d   v0, v4
	ld1.4s      {v4},[data], #16

	uadalp.2d   v1, v5
	ld1.4s      {v5},[data], #16

	uadalp.2d   v2, v6
	ld1.4s      {v6},[data], #16

	uadalp.2d   v3, v7
	ld1.4s      {v7},[data], #16

	b.ge        L64_loop

L64_finishup:
	uadalp.2d   v0, v4
	uadalp.2d   v1, v5
	uadalp.2d   v2, v6
	uadalp.2d   v3, v7

	add.2d      v0, v0, v1
	add.2d      v2, v2, v3
	addp.2d     d0, v0
	addp.2d     d2, v2
	add.2d      v0, v0, v2
	fmov        x7, d0			// partial in x7 now

	// restore used vector registers
	ld1.4s      {v0, v1, v2, v3}, [sp], #4*16
	ld1.4s      {v4, v5, v6, v7}, [sp], #4*16

L32_bytes:
	tst     mlen, #32
	b.eq    L16_bytes
	ldp	x9, x10, [data], #16
	ldp	x11, x12, [data], #16
	adds	x7, x7, x9
	mov	x9, #0
	adcs	x7, x7, x10
	adcs	x7, x7, x11
	adcs	x7, x7, x12
	adc	x7, x7, x9

L16_bytes:
	tst	mlen, #16
	b.eq	L8_bytes
	ldp	x9, x10, [data], #16
	adds	x7, x7, x9
	mov	x9, #0
	adcs	x7, x7, x10
	adc	x7, x7, x9

L8_bytes:
	tst     mlen, #8
	mov	x10, #0
	b.eq    L4_bytes
	ldr	x9,[data],#8
	adds	x7, x7, x9
	adc	x7, x7, x10

L4_bytes:
	tst     mlen, #4
	b.eq    L2_bytes
	ldr	w9,[data],#4
	adds	x7, x7, x9
	adc	x7, x7, x10

L2_bytes:
	tst	mlen, #2
	b.eq	L_trailing_bytes
	ldrh	w9,[data],#2
	adds	x7, x7, x9
	adc	x7, x7, x10

L_trailing_bytes:
	tst     mlen, #1
	b.eq    L0_bytes
	ldrb	w9,[data],#1
	adds	x7, x7, x9
	adc	x7, x7, x10
	eor	started_on_odd, started_on_odd, #1

L0_bytes:
/*
 *		if (needs_swap)
 *			partial = (partial << 8) + (partial >> 56);
 */
	cbz	needs_swap, 1f
	ror	x7, x7, #56
1:
/*
 *		sum += (partial >> 32) + (partial & 0xffffffff);
 *		sum = (sum >> 32) + (sum & 0xffffffff);
 *	}
 */

	add	x3, x3, x7, lsr #32
	mov	w7, w7
	add	x3, x3, x7
	mov	w7, w3
	add	x3, x7, x3, lsr #32

L_continue:
	cmp	len, #0
	ldr     ptr_m, [m, #M_NEXT]			// m = m->m_next
	b.gt	L_loop

/*
 *	final_acc = (sum >> 48) + ((sum >> 32) & 0xffff) +
 *	    ((sum >> 16) & 0xffff) + (sum & 0xffff);
 *	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
 *	final_acc = (final_acc >> 16) + (final_acc & 0xffff);
 *	return (final_acc & 0xffff);
 * }
 */

	mov	w4, #0x00ffff
	and	x0, x4, x3, lsr #48
	and	x1, x4, x3, lsr #32
	and	x2, x4, x3, lsr #16
	and	x3, x4, x3
	add	w0, w0, w1
	add	w2, w2, w3
	add	w0, w0, w2
	and	w1, w4, w0, lsr #16
	and	w0, w4, w0
	add	w0, w0, w1
	and	w1, w4, w0, lsr #16
	and	w0, w4, w0
	add	w0, w0, w1
	/*
	 * If we were to 1's complement it (XOR with 0xffff):
	 *
	 * eor    	w0, w0, w4
	 */
	and	w0, w0, w4

	ret	lr

Lin_cksum_whoops:
	adrp	x0, Lin_cksum_whoops_str@page
	add	x0, x0, Lin_cksum_whoops_str@pageoff
	bl	#CKSUM_ERR
	mov	x0, #-1
	ret	lr

Lin_cksum_whoops_str:
	.asciz	"os_cpu_in_cksum_mbuf: out of data\n"
	.align	5
