/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/mbuf.h>
#include <sys/kdebug.h>

#define DBG_FNC_IN_CKSUM	NETDBG_CODE(DBG_NETIP, (3 << 8))

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */

union s_util {
        char    c[2];
        u_short s;
};

union l_util {
        u_int16_t s[2];
        u_int32_t l;   
};

union q_util {
        u_int16_t s[4];
        u_int32_t l[2];
        u_int64_t q;
};    

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)

#define REDUCE32                                                          \
    {                                                                     \
        q_util.q = sum;                                                   \
        sum = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3];      \
    }
#define REDUCE16                                                          \
    {                                                                     \
        q_util.q = sum;                                                   \
        l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
        sum = l_util.s[0] + l_util.s[1];                                  \
        ADDCARRY(sum);                                                    \
    }

#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

                
#if defined(ppc)

__inline unsigned short
in_addword(u_short a, u_short b)
{
        union l_util l_util;   
	u_int32_t sum = a + b;
	REDUCE;
	return (sum);
}

__inline unsigned short
in_pseudo(u_int a, u_int b, u_int c)
{
        u_int64_t sum;
        union q_util q_util;
        union l_util l_util;   

        sum = (u_int64_t) a + b + c;
        REDUCE16;
        return (sum);

}

int
in_cksum(m, len)
	register struct mbuf *m;
	register int len;
{
	register u_short *w;
	register int sum = 0;
	register int mlen = 0;
	int starting_on_odd  = 0;


	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_START, len,0,0,0,0);

	for (;m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		mlen = m->m_len;
		w = mtod(m, u_short *);

		if (len < mlen)
			mlen = len;

		sum = xsum_assym(w, mlen, sum, starting_on_odd);
		len -= mlen;
		if (mlen & 0x1)
		{
		    if (starting_on_odd)
			starting_on_odd = 0;
		    else
			starting_on_odd = 1;
		}
	}

	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_END, 0,0,0,0,0);
	return (~sum & 0xffff);
}

u_short
in_cksum_skip(m, len, skip)
        register struct mbuf *m;
        register int len;
        register int skip;
{
	register u_short *w;
	register int sum = 0;
	register int mlen = 0;
	int starting_on_odd  = 0;

	len -= skip;
        for (; skip && m; m = m->m_next) {
                if (m->m_len > skip) {
                        mlen = m->m_len - skip;
			w = (u_short *)(m->m_data+skip);
                        goto skip_start;
                } else {    
                        skip -= m->m_len;
                }
        }
	for (;m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		mlen = m->m_len;
		w = mtod(m, u_short *);

		if (len < mlen)
			mlen = len;
skip_start:
		sum = xsum_assym(w, mlen, sum, starting_on_odd);
		len -= mlen;
		if (mlen & 0x1)
		{
		    if (starting_on_odd)
			starting_on_odd = 0;
		    else
			starting_on_odd = 1;
		}
	}

	return (~sum & 0xffff);
}
#else

u_short 
in_addword(u_short a, u_short b)
{       
        union l_util l_util;   
        u_int32_t sum = a + b;
        REDUCE(sum);
        return (sum);
}       

u_short
in_pseudo(u_int a, u_int b, u_int c)
{
        u_int64_t sum;  
        union q_util q_util;
        union l_util l_util;   

        sum = (u_int64_t) a + b + c;
        REDUCE16;
        return (sum);
}


int
in_cksum(m, len)
	register struct mbuf *m;
	register int len;
{
	register u_short *w;
	register int sum = 0;
	register int mlen = 0;
	int byte_swapped = 0;
	union s_util s_util;
	union l_util l_util;   

	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_START, len,0,0,0,0);

	for (;m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		w = mtod(m, u_short *);
		if (mlen == -1) {
			/*
			 * The first byte of this mbuf is the continuation
			 * of a word spanning between this mbuf and the
			 * last mbuf.
			 *
			 * s_util.c[0] is already saved when scanning previous
			 * mbuf.
			 */
			s_util.c[1] = *(char *)w;
			sum += s_util.s;
			w = (u_short *)((char *)w + 1);
			mlen = m->m_len - 1;
			len--;
		} else
			mlen = m->m_len;
		if (len < mlen)
			mlen = len;
		len -= mlen;
		/*
		 * Force to even boundary.
		 */
		if ((1 & (int) w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(u_char *)w;
			w = (u_short *)((char *)w + 1);
			mlen--;
			byte_swapped = 1;
		}
		/*
		 * Unroll the loop to make overhead from
		 * branches &c small.
		 */
		while ((mlen -= 32) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
			sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}
		mlen += 32;
		while ((mlen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}
		mlen += 8;
		if (mlen == 0 && byte_swapped == 0)
			continue;
		REDUCE;
		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}
		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;
			if (mlen == -1) {
				s_util.c[1] = *(char *)w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(char *)w;
	}
	if (len)
		printf("cksum: out of data\n");
	if (mlen == -1) {
		/* The last mbuf has odd # of bytes. Follow the
		   standard (the odd byte may be shifted left by 8 bits
		   or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_END, 0,0,0,0,0);
	return (~sum & 0xffff);
}

int
in_cksum_skip(m, len, skip)
	register struct mbuf *m;
	register u_short len;
	register u_short skip;
{
	register u_short *w;
	register int sum = 0;
	register int mlen = 0;
	int byte_swapped = 0;
	union s_util s_util;
	union l_util l_util;   

	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_START, len,0,0,0,0);

	len -= skip;
        for (; skip && m; m = m->m_next) {
                if (m->m_len > skip) {
                        mlen = m->m_len - skip;
			w = (u_short *)(m->m_data+skip);
                        goto skip_start;
                } else {    
                        skip -= m->m_len;
                }
        }
	for (;m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		w = mtod(m, u_short *);

		if (mlen == -1) {
			/*
			 * The first byte of this mbuf is the continuation
			 * of a word spanning between this mbuf and the
			 * last mbuf.
			 *
			 * s_util.c[0] is already saved when scanning previous
			 * mbuf.
			 */
			s_util.c[1] = *(char *)w;
			sum += s_util.s;
			w = (u_short *)((char *)w + 1);
			mlen = m->m_len - 1;
			len--;
		} else {
		  mlen = m->m_len;
		}
		  if (len < mlen)
		    mlen = len;
skip_start:

		len -= mlen;
		/*
		 * Force to even boundary.
		 */
		if ((1 & (int) w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(u_char *)w;
			w = (u_short *)((char *)w + 1);
			mlen--;
			byte_swapped = 1;
		}
		/*
		 * Unroll the loop to make overhead from
		 * branches &c small.
		 */
		while ((mlen -= 32) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
			sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}
		mlen += 32;
		while ((mlen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}
		mlen += 8;
		if (mlen == 0 && byte_swapped == 0)
			continue;
		REDUCE;
		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}
		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;
			if (mlen == -1) {
				s_util.c[1] = *(char *)w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(char *)w;
	}
	if (len)
		printf("cksum: out of data\n");
	if (mlen == -1) {
		/* The last mbuf has odd # of bytes. Follow the
		   standard (the odd byte may be shifted left by 8 bits
		   or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	KERNEL_DEBUG(DBG_FNC_IN_CKSUM | DBG_FUNC_END, 0,0,0,0,0);
	return (~sum & 0xffff);
}

#endif
