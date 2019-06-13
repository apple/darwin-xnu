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
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
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
 *      @(#)bpf_filter.c	8.1 (Berkeley) 6/10/93
 *
 * $FreeBSD: src/sys/net/bpf_filter.c,v 1.17 1999/12/29 04:38:31 peter Exp $
 */

#include <sys/param.h>
#include <string.h>

#ifdef sun
#include <netinet/in.h>
#endif

#ifdef KERNEL
#include <sys/mbuf.h>
#endif
#include <net/bpf.h>
#ifdef KERNEL

extern unsigned int bpf_maxbufsize;

static inline u_int32_t
get_word_from_buffers(u_char * cp, u_char * np, int num_from_cp)
{
	u_int32_t	val;

	switch (num_from_cp) {
	case 1:
		val = ((u_int32_t)cp[0] << 24) |
			((u_int32_t)np[0] << 16) |
			((u_int32_t)np[1] << 8)  |
			(u_int32_t)np[2];
		break;

	case 2:
		val = ((u_int32_t)cp[0] << 24) |
			((u_int32_t)cp[1] << 16) |
			((u_int32_t)np[0] << 8) |
			(u_int32_t)np[1];
		break;
	default:
		val = ((u_int32_t)cp[0] << 24) |
			((u_int32_t)cp[1] << 16) |
			((u_int32_t)cp[2] << 8) |
			(u_int32_t)np[0];
		break;
	}
	return (val);
}

static u_char *
m_hdr_offset(struct mbuf **m_p, void * hdr, size_t hdrlen, bpf_u_int32 * k_p,
    size_t * len_p)
{
	u_char	*cp;
	bpf_u_int32 k = *k_p;
	size_t len;

	if (k >= hdrlen) {
		struct mbuf *m = *m_p;

		/* there's no header or the offset we want is past the header */
		k -= hdrlen;
		len = m->m_len;
		while (k >= len) {
			k -= len;
			m = m->m_next;
			if (m == NULL)
				return (NULL);
			len = m->m_len;
		}
		cp = mtod(m, u_char *) + k;

		/* return next mbuf, in case it's needed */
		*m_p = m->m_next;

		/* update the offset */
		*k_p = k;
	} else {
		len = hdrlen;
		cp = (u_char *)hdr + k;
	}
	*len_p = len;
	return (cp);
}

static u_int32_t
m_xword(struct mbuf *m, void * hdr, size_t hdrlen, bpf_u_int32 k, int *err)
{
	size_t len;
	u_char *cp, *np;

	cp = m_hdr_offset(&m, hdr, hdrlen, &k, &len);
	if (cp == NULL)
		goto bad;
	if (len - k >= 4) {
		*err = 0;
		return EXTRACT_LONG(cp);
	}
	if (m == 0 || m->m_len + len - k < 4)
		goto bad;
	*err = 0;
	np = mtod(m, u_char *);
	return get_word_from_buffers(cp, np, len - k);

    bad:
	*err = 1;
	return 0;
}

static u_int16_t
m_xhalf(struct mbuf *m, void * hdr, size_t hdrlen, bpf_u_int32 k, int *err)
{
	size_t len;
	u_char *cp;

	cp = m_hdr_offset(&m, hdr, hdrlen, &k, &len);
	if (cp == NULL)
		goto bad;
	if (len - k >= 2) {
		*err = 0;
		return EXTRACT_SHORT(cp);
	}
	if (m == 0)
		goto bad;
	*err = 0;
	return (cp[0] << 8) | mtod(m, u_char *)[0];
 bad:
	*err = 1;
	return 0;
}

static u_int8_t
m_xbyte(struct mbuf *m, void * hdr, size_t hdrlen, bpf_u_int32 k, int *err)
{
	size_t len;
	u_char *cp;

	cp = m_hdr_offset(&m, hdr, hdrlen, &k, &len);
	if (cp == NULL)
		goto bad;
	*err = 0;
	return (*cp);
 bad:
	*err = 1;
	return 0;

}


static u_int32_t
bp_xword(struct bpf_packet *bp, bpf_u_int32 k, int *err)
{
	void * 	hdr = bp->bpfp_header;
	size_t	hdrlen = bp->bpfp_header_length;

	switch (bp->bpfp_type) {
	case BPF_PACKET_TYPE_MBUF:
		return m_xword(bp->bpfp_mbuf, hdr, hdrlen, k, err);
	default:
		break;
	}
	*err = 1;
	return 0;

}

static u_int16_t
bp_xhalf(struct bpf_packet *bp, bpf_u_int32 k, int *err)
{
	void * 	hdr = bp->bpfp_header;
	size_t	hdrlen = bp->bpfp_header_length;

	switch (bp->bpfp_type) {
	case BPF_PACKET_TYPE_MBUF:
		return m_xhalf(bp->bpfp_mbuf, hdr, hdrlen, k, err);
	default:
		break;
	}
	*err = 1;
	return 0;

}

static u_int8_t
bp_xbyte(struct bpf_packet *bp, bpf_u_int32 k, int *err)
{
	void * 	hdr = bp->bpfp_header;
	size_t	hdrlen = bp->bpfp_header_length;

	switch (bp->bpfp_type) {
	case BPF_PACKET_TYPE_MBUF:
		return m_xbyte(bp->bpfp_mbuf, hdr, hdrlen, k, err);
	default:
		break;
	}
	*err = 1;
	return 0;

}

#endif

/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 */
u_int
bpf_filter(const struct bpf_insn *pc, u_char *p, u_int wirelen, u_int buflen)
{
	u_int32_t A = 0, X = 0;
	bpf_u_int32 k;
	int32_t mem[BPF_MEMWORDS];
#ifdef KERNEL
	int merr;
	struct bpf_packet * bp = (struct bpf_packet *)(void *)p;
#endif /* KERNEL */

	bzero(mem, sizeof(mem));

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (u_int)-1;

	--pc;
	while (1) {
		++pc;
		switch (pc->code) {

		default:
#ifdef KERNEL
			return 0;
#else /* KERNEL */
			abort();
#endif /* KERNEL */
		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int32_t) > buflen - k) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xword(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
#if BPF_ALIGN
			if (((intptr_t)(p + k) & 3) != 0)
				A = EXTRACT_LONG(&p[k]);
			else
#endif /* BPF_ALIGN */
				A = ntohl(*(int32_t *)(void *)(p + k));
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int16_t) > buflen - k) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xhalf(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			if (k >= buflen) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xbyte(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
			A = p[k];
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (pc->k > buflen || X > buflen - pc->k ||
			    sizeof(int32_t) > buflen - k) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xword(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
#if BPF_ALIGN
			if (((intptr_t)(p + k) & 3) != 0)
				A = EXTRACT_LONG(&p[k]);
			else
#endif /* BPF_ALIGN */
				A = ntohl(*(int32_t *)(void *)(p + k));
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (X > buflen || pc->k > buflen - X ||
			    sizeof(int16_t) > buflen - k) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xhalf(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if (pc->k >= buflen || X >= buflen - pc->k) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				A = bp_xbyte(bp, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else /* KERNEL */
				return 0;
#endif /* KERNEL */
			}
			A = p[k];
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if (k >= buflen) {
#ifdef KERNEL
				if (buflen != 0)
					return 0;
				X = bp_xbyte(bp, k, &merr);
				if (merr != 0)
					return 0;
				X = (X & 0xf) << 2;
				continue;
#else
				return 0;
#endif
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_ST:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			A = -A;
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

#ifdef KERNEL
/*
 * Return true if the 'fcode' is a valid filter program.
 * The constraints are that each jump be forward and to a valid
 * code, that memory accesses are within valid ranges (to the 
 * extent that this can be checked statically; loads of packet data
 * have to be, and are, also checked at run time), and that
 * the code terminates with either an accept or reject.
 *
 * The kernel needs to be able to verify an application's filter code.
 * Otherwise, a bogus program could easily crash the system.
 */
int
bpf_validate(const struct bpf_insn *f, int len)
{
	u_int i, from;
	const struct bpf_insn *p;

	if (len < 1 || len > BPF_MAXINSNS)
		return 0;
	
	for (i = 0; i < ((u_int)len); ++i) {
		p = &f[i];
		switch (BPF_CLASS(p->code)) {
			/*
			 * Check that memory operations use valid addresses
			 */
			case BPF_LD:
			case BPF_LDX:
				switch (BPF_MODE(p->code)) {
					case BPF_IMM:
						break;
					case BPF_ABS:
					case BPF_IND:
					case BPF_MSH:
						/*
						 * More strict check with actual packet length
						 * is done runtime.
						 */
						if (p->k >= bpf_maxbufsize)
							return 0;
						break;
					case BPF_MEM:
						if (p->k >= BPF_MEMWORDS)
							return 0;
						break;
					case BPF_LEN:
						break;
					default:
						return 0;
				}
				break;
			case BPF_ST:
			case BPF_STX:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_ALU:
				switch (BPF_OP(p->code)) {
					case BPF_ADD:
					case BPF_SUB:
					case BPF_MUL:
					case BPF_OR:
					case BPF_AND:
					case BPF_LSH:
					case BPF_RSH:
					case BPF_NEG:
						break;
					case BPF_DIV:
						/* 
						 * Check for constant division by 0
						 */
						if(BPF_SRC(p->code) == BPF_K && p->k == 0)
							return 0;
						break;
					default:
						return 0;
				}
				break;
			case BPF_JMP:
				/*
				 * Check that jumps are within the code block,
				 * and that unconditional branches don't go 
				 * backwards as a result of an overflow.
				 * Unconditional branches have a 32-bit offset,
				 * so they could overflow; we check to make 
				 * sure they don't. Conditional branches have 
				 * an 8-bit offset, and the from address is 
				 * less than equal to BPF_MAXINSNS, and we assume that
				 * BPF_MAXINSNS is sufficiently small that adding 255 
				 * to it won't overlflow
				 *
				 * We know that len is <= BPF_MAXINSNS, and we 
				 * assume that BPF_MAXINSNS is less than the maximum 
				 * size of a u_int, so that i+1 doesn't overflow
				 */
				from = i+1;
				switch (BPF_OP(p->code)) {
					case BPF_JA:
						if (from + p->k < from || from + p->k >= ((u_int)len))
							return 0;
						break;
					case BPF_JEQ:
					case BPF_JGT:
					case BPF_JGE:
					case BPF_JSET:
						if (from + p->jt >= ((u_int)len) || from + p->jf >= ((u_int)len))
							return 0;
						break;
					default:
						return 0;
				}
				break;
			case BPF_RET:
				break;
			case BPF_MISC:
				break;
			default:
				return 0;
		}
	}
		return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
#endif
