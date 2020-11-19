/*
 * Copyright (c) 2000-2016 Apple Computer, Inc. All rights reserved.
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
#include <stdint.h> // For uintptr_t.
#include <string.h>
#include <libkern/mkext.h>


#define BASE 65521L /* largest prime smaller than 65536 */
#define NMAX 5552  // the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1

#define DO1(buf, i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf, i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf, i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf, i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

u_int32_t
mkext_adler32(uint8_t *buf, int32_t len)
{
	unsigned long s1 = 1; // adler & 0xffff;
	unsigned long s2 = 0; // (adler >> 16) & 0xffff;
	int k;


	while (len > 0) {
		k = len < NMAX ? len : NMAX;
		len -= k;
		while (k >= 16) {
			DO16(buf);
			buf += 16;
			k -= 16;
		}
		if (k != 0) {
			do {
				s1 += *buf++;
				s2 += s1;
			} while (--k);
		}
		s1 %= BASE;
		s2 %= BASE;
	}
	return (u_int32_t)((s2 << 16) | s1);
}


/**************************************************************
*   LZSS.C -- A Data Compression Program
***************************************************************
*    4/6/1989 Haruhiko Okumura
*    Use, distribute, and modify this program freely.
*    Please send me your improved versions.
*        PC-VAN      SCIENCE
*        NIFTY-Serve PAF01022
*        CompuServe  74050,1022
*
**************************************************************/

#define N         4096  /* size of ring buffer - must be power of 2 */
#define F         18    /* upper limit for match_length */
#define THRESHOLD 2     /* encode string into position and length
	                 *  if match_length is greater than this */
#if !KERNEL
#define NIL       N     /* index for root of binary search trees */
#endif

struct encode_state {
	/*
	 * left & right children & parent. These constitute binary search trees.
	 */
	int lchild[N + 1], rchild[N + 257], parent[N + 1];

	/* ring buffer of size N, with extra F-1 bytes to aid string comparison */
	u_int8_t text_buf[N + F - 1];

	/*
	 * match_length of longest match.
	 * These are set by the insert_node() procedure.
	 */
	int match_position, match_length;
};


int
decompress_lzss(u_int8_t *dst, u_int32_t dstlen, u_int8_t *src, u_int32_t srclen)
{
	/* ring buffer of size N, with extra F-1 bytes to aid string comparison */
	u_int8_t text_buf[N + F - 1];
	u_int8_t *dststart = dst;
	u_int8_t *dstend = dst + dstlen;
	u_int8_t *srcend = src + srclen;
	int  i, j, k, r;
	u_int8_t c;
	unsigned int flags;

	dst = dststart;
	srcend = src + srclen;
	for (i = 0; i < N - F; i++) {
		text_buf[i] = ' ';
	}
	r = N - F;
	flags = 0;
	for (;;) {
		if (((flags >>= 1) & 0x100) == 0) {
			if (src < srcend) {
				c = *src++;
			} else {
				break;
			}
			flags = c | 0xFF00; /* uses higher byte cleverly */
		} /* to count eight */
		if (flags & 1) {
			if (src < srcend) {
				c = *src++;
			} else {
				break;
			}
			*dst++ = c;
			if (dst >= dstend) {
				goto finish;
			}
			text_buf[r++] = c;
			r &= (N - 1);
		} else {
			if (src < srcend) {
				i = *src++;
			} else {
				break;
			}
			if (src < srcend) {
				j = *src++;
			} else {
				break;
			}
			i |= ((j & 0xF0) << 4);
			j  =  (j & 0x0F) + THRESHOLD;
			for (k = 0; k <= j; k++) {
				c = text_buf[(i + k) & (N - 1)];
				*dst++ = c;
				if (dst >= dstend) {
					goto finish;
				}
				text_buf[r++] = c;
				r &= (N - 1);
			}
		}
	}
finish:
	return (int)(dst - dststart);
}

#if !KERNEL

/*
 * initialize state, mostly the trees
 *
 * For i = 0 to N - 1, rchild[i] and lchild[i] will be the right and left
 * children of node i.  These nodes need not be initialized.  Also, parent[i]
 * is the parent of node i.  These are initialized to NIL (= N), which stands
 * for 'not used.'  For i = 0 to 255, rchild[N + i + 1] is the root of the
 * tree for strings that begin with character i.  These are initialized to NIL.
 * Note there are 256 trees. */
static void
init_state(struct encode_state *sp)
{
	int  i;

	bzero(sp, sizeof(*sp));

	for (i = 0; i < N - F; i++) {
		sp->text_buf[i] = ' ';
	}
	for (i = N + 1; i <= N + 256; i++) {
		sp->rchild[i] = NIL;
	}
	for (i = 0; i < N; i++) {
		sp->parent[i] = NIL;
	}
}

/*
 * Inserts string of length F, text_buf[r..r+F-1], into one of the trees
 * (text_buf[r]'th tree) and returns the longest-match position and length
 * via the global variables match_position and match_length.
 * If match_length = F, then removes the old node in favor of the new one,
 * because the old one will be deleted sooner. Note r plays double role,
 * as tree node and position in buffer.
 */
static void
insert_node(struct encode_state *sp, int r)
{
	int  i, p, cmp;
	u_int8_t  *key;

	cmp = 1;
	key = &sp->text_buf[r];
	p = N + 1 + key[0];
	sp->rchild[r] = sp->lchild[r] = NIL;
	sp->match_length = 0;
	for (;;) {
		if (cmp >= 0) {
			if (sp->rchild[p] != NIL) {
				p = sp->rchild[p];
			} else {
				sp->rchild[p] = r;
				sp->parent[r] = p;
				return;
			}
		} else {
			if (sp->lchild[p] != NIL) {
				p = sp->lchild[p];
			} else {
				sp->lchild[p] = r;
				sp->parent[r] = p;
				return;
			}
		}
		for (i = 1; i < F; i++) {
			if ((cmp = key[i] - sp->text_buf[p + i]) != 0) {
				break;
			}
		}
		if (i > sp->match_length) {
			sp->match_position = p;
			if ((sp->match_length = i) >= F) {
				break;
			}
		}
	}
	sp->parent[r] = sp->parent[p];
	sp->lchild[r] = sp->lchild[p];
	sp->rchild[r] = sp->rchild[p];
	sp->parent[sp->lchild[p]] = r;
	sp->parent[sp->rchild[p]] = r;
	if (sp->rchild[sp->parent[p]] == p) {
		sp->rchild[sp->parent[p]] = r;
	} else {
		sp->lchild[sp->parent[p]] = r;
	}
	sp->parent[p] = NIL; /* remove p */
}

/* deletes node p from tree */
static void
delete_node(struct encode_state *sp, int p)
{
	int  q;

	if (sp->parent[p] == NIL) {
		return; /* not in tree */
	}
	if (sp->rchild[p] == NIL) {
		q = sp->lchild[p];
	} else if (sp->lchild[p] == NIL) {
		q = sp->rchild[p];
	} else {
		q = sp->lchild[p];
		if (sp->rchild[q] != NIL) {
			do {
				q = sp->rchild[q];
			} while (sp->rchild[q] != NIL);
			sp->rchild[sp->parent[q]] = sp->lchild[q];
			sp->parent[sp->lchild[q]] = sp->parent[q];
			sp->lchild[q] = sp->lchild[p];
			sp->parent[sp->lchild[p]] = q;
		}
		sp->rchild[q] = sp->rchild[p];
		sp->parent[sp->rchild[p]] = q;
	}
	sp->parent[q] = sp->parent[p];
	if (sp->rchild[sp->parent[p]] == p) {
		sp->rchild[sp->parent[p]] = q;
	} else {
		sp->lchild[sp->parent[p]] = q;
	}
	sp->parent[p] = NIL;
}

#endif /* !KERNEL */
