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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)iso_chksum.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/* 
 * ISO CHECKSUM
 *
 * The checksum generation and check routines are here.
 * The checksum is 2 bytes such that the sum of all the bytes b(i) == 0
 * and the sum of i * b(i) == 0.
 * The whole thing is complicated by the fact that the data are in mbuf
 * chains.
 * Furthermore, there is the possibility of wraparound in the running
 * sums after adding up 4102 octets.  In order to avoid doing a mod
 * operation after EACH add, we have restricted this implementation to 
 * negotiating a maximum of 4096-octets per TPDU (for the transport layer).
 * The routine iso_check_csum doesn't need to know where the checksum
 * octets are.
 * The routine iso_gen_csum takes a pointer to an mbuf chain (logically
 * a chunk of data), an offset into the chunk at which the 2 octets are to
 * be stuffed, and the length of the chunk.  The 2 octets have to be
 * logically adjacent, but may be physically located in separate mbufs.
 */

#include <sys/param.h>
#include <sys/systm.h>

#if ISO
#include <netiso/argo_debug.h>
#include <sys/mbuf.h>
#endif /* ISO */

#ifndef MNULL
#define MNULL (struct mbuf *)0
#endif /* MNULL */

/*
 * FUNCTION:	iso_check_csum
 *
 * PURPOSE:		To check the checksum of the packet in the mbuf chain (m).
 * 				The total length of the packet is (len).
 * 				Called from tp_input() and clnp_intr()
 *
 * RETURNS:		 TRUE (something non-zero) if there is a checksum error,
 * 			 	 FALSE if there was NO checksum error.
 *
 * SIDE EFFECTS:  none
 *
 * NOTES:		 It might be possible to gain something by optimizing
 *               this routine (unrolling loops, etc). But it is such
 *				 a horrible thing to fiddle with anyway, it probably
 *				 isn't worth it.
 */
int 
iso_check_csum(m, len)
	struct mbuf *m;
	int len;
{
	register u_char *p = mtod(m, u_char *);
	register u_long c0=0, c1=0;
	register int i=0;
	int cume = 0; /* cumulative length */
	int l;

	l = len;
	len = min(m->m_len, len);
	i = 0;

	IFDEBUG(D_CHKSUM)
		printf("iso_check_csum: m x%x, l x%x, m->m_len x%x\n", m, l, m->m_len);
	ENDDEBUG

	while( i<l ) {
		cume += len;
		while (i<cume) {
			c0 = c0 + *(p++);
			c1 += c0;
			i++;
		}
		if(i < l) {
			m = m->m_next;
			IFDEBUG(D_CHKSUM)
				printf("iso_check_csum: new mbuf\n");
				if(l-i < m->m_len)
					printf(
					"bad mbuf chain in check csum l 0x%x i 0x%x m_data 0x%x",
						l,i,m->m_data);
			ENDDEBUG
			ASSERT( m != MNULL);
			len = min( m->m_len, l-i);
			p = mtod(m, u_char *);
		}
	}
	if ( ((int)c0 % 255) || ((int)c1 % 255) ) {
		IFDEBUG(D_CHKSUM)
			printf("BAD iso_check_csum l 0x%x cume 0x%x len 0x%x, i 0x%x", 
				l, cume, len, i);
		ENDDEBUG
		return ((int)c0 % 255)<<8 | ((int)c1 % 255);
	}
	return 0;
}

/*
 * FUNCTION:	iso_gen_csum
 *
 * PURPOSE:		To generate the checksum of the packet in the mbuf chain (m).
 * 				The first of the 2 (logically) adjacent checksum bytes 
 *				(x and y) go at offset (n).
 * 				(n) is an offset relative to the beginning of the data, 
 *				not the beginning of the mbuf.
 * 				(l) is the length of the total mbuf chain's data.
 * 				Called from tp_emit(), tp_error_emit()
 *				clnp_emit_er(), clnp_forward(), clnp_output().
 *
 * RETURNS:		Rien
 *
 * SIDE EFFECTS: Puts the 2 checksum bytes into the packet.
 *
 * NOTES:		Ditto the note for iso_check_csum().
 */

void
iso_gen_csum(m,n,l)
	struct mbuf *m;
	int n; /* offset of 2 checksum bytes */
	int l;
{
	register u_char *p = mtod(m, u_char *);
	register int c0=0, c1=0;
	register int i=0;
	int loc = n++, len=0; /* n is position, loc is offset */
	u_char *xloc;
	u_char *yloc;
	int cume=0;	/* cume == cumulative length */

	IFDEBUG(D_CHKSUM)
		printf("enter gen csum m 0x%x n 0x%x l 0x%x\n",m, n-1 ,l );
	ENDDEBUG

	while(i < l) {
		len = min(m->m_len, CLBYTES);
		/* RAH: don't cksum more than l bytes */
		len = min(len, l - i);

		cume +=len;
		p = mtod(m, u_char *);

		if(loc>=0) {
			if (loc < len) {
				xloc = loc + mtod(m, u_char *);
				IFDEBUG(D_CHKSUM)
					printf("1: zeroing xloc 0x%x loc 0x%x\n",xloc, loc );
				ENDDEBUG
				*xloc = (u_char)0;
				if (loc+1 < len) {
					/* both xloc and yloc are in same mbuf */
					yloc = 1  + xloc;
					IFDEBUG(D_CHKSUM)
						printf("2: zeroing yloc 0x%x loc 0x%x\n",yloc, loc );
					ENDDEBUG
					*yloc = (u_char)0;
				} else {
					/* crosses boundary of mbufs */
					yloc = mtod(m->m_next, u_char *);
					IFDEBUG(D_CHKSUM)
						printf("3: zeroing yloc 0x%x \n",yloc );
					ENDDEBUG
					*yloc = (u_char)0;
				}
			}
			loc -= len;
		}

		while(i < cume) {
			c0 = (c0 + *p);
			c1 += c0 ;
			i++; 
			p++;
		}
		m = m->m_next;
	}
	IFDEBUG(D_CHKSUM)
		printf("gen csum final xloc 0x%x yloc 0x%x\n",xloc, yloc );
	ENDDEBUG

	c1 = (((c0 * (l-n))-c1)%255) ;
	*xloc = (u_char) ((c1 < 0)? c1+255 : c1);

	c1 = (-(int)(c1+c0))%255;
	*yloc = (u_char) (c1 < 0? c1 + 255 : c1);

	IFDEBUG(D_CHKSUM)
		printf("gen csum end \n");
	ENDDEBUG
}

/*
 * FUNCTION:	m_datalen
 *
 * PURPOSE:		returns length of the mbuf chain.
 * 				used all over the iso code.
 *
 * RETURNS:		integer
 *
 * SIDE EFFECTS: none
 *
 * NOTES:		
 */

int
m_datalen (m)
	register struct mbuf *m;
{ 	
	register int datalen;

	for (datalen = 0; m; m = m->m_next)
		datalen += m->m_len;
	return datalen;
}

int
m_compress(in, out)
	register struct mbuf *in, **out;
{
	register 	int datalen = 0;
	int	s = splimp();

	if( in->m_next == MNULL ) {
		*out = in;
		IFDEBUG(D_REQUEST)
			printf("m_compress returning 0x%x: A\n", in->m_len);
		ENDDEBUG
		splx(s);
		return in->m_len;
	}
	MGET((*out), M_DONTWAIT, MT_DATA);
	if((*out) == MNULL) {
		*out = in;
		IFDEBUG(D_REQUEST)
			printf("m_compress returning -1: B\n");
		ENDDEBUG
		splx(s);
		return -1; 
	}
	(*out)->m_len = 0;
	(*out)->m_act = MNULL;

	while (in) {
		IFDEBUG(D_REQUEST)
			printf("m_compress in 0x%x *out 0x%x\n", in, *out);
			printf("m_compress in: len 0x%x, off 0x%x\n", in->m_len, in->m_data);
			printf("m_compress *out: len 0x%x, off 0x%x\n", (*out)->m_len, 
				(*out)->m_data);
		ENDDEBUG
		if (in->m_flags & M_EXT) {
			ASSERT(in->m_len == 0);
		}
		if ( in->m_len == 0) {
			in = in->m_next;
			continue;
		}
		if (((*out)->m_flags & M_EXT) == 0) {
			int len;

			len = M_TRAILINGSPACE(*out);
			len = min(len, in->m_len);
			datalen += len;

			IFDEBUG(D_REQUEST)
				printf("m_compress copying len %d\n", len);
			ENDDEBUG
			bcopy(mtod(in, caddr_t), mtod((*out), caddr_t) + (*out)->m_len,
						(unsigned)len);

			(*out)->m_len += len;
			in->m_len -= len;
			continue;
		} else {
			/* (*out) is full */
			if(( (*out)->m_next = m_get(M_DONTWAIT, MT_DATA) ) == MNULL) {
				m_freem(*out);
				*out = in;
				IFDEBUG(D_REQUEST)
					printf("m_compress returning -1: B\n");
				ENDDEBUG
				splx(s);
				return -1;
			}
			(*out)->m_len = 0;
			(*out)->m_act = MNULL;
			*out = (*out)->m_next;
		}
	}
	m_freem(in);
	IFDEBUG(D_REQUEST)
		printf("m_compress returning 0x%x: A\n", datalen);
	ENDDEBUG
	splx(s);
	return datalen;
}
