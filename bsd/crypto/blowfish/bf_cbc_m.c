/*
 * heavily modified to accept mbuf, by Jun-ichiro itojun Itoh
 * <itojun@itojun.org>, 1997.
 */
/* crypto/bf/bf_cbc.c */
/* Copyright (C) 1995-1997 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@mincom.oz.au).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@mincom.oz.au)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@mincom.oz.au)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <crypto/blowfish/blowfish.h>
#include <crypto/blowfish/bf_locl.h>

#define panic(x) {printf(x); return;}

void BF_cbc_encrypt_m(m0, skip, length, key, iv, mode)
	struct mbuf *m0;
	int skip;
	int length;
	BF_KEY *key;
	unsigned char *iv;
	int mode;
{
	u_int8_t inbuf[8], outbuf[8];
	struct mbuf *m;
	size_t off;
	register BF_LONG tin0, tin1;
	register BF_LONG tout0, tout1;
	BF_LONG tin[2];

	/* sanity checks */
	if (m0->m_pkthdr.len < skip) {
		printf("mbuf length < skip\n");
		return;
	}
	if (m0->m_pkthdr.len < length) {
		printf("mbuf length < encrypt length\n");
		return;
	}
	if (m0->m_pkthdr.len < skip + length) {
		printf("mbuf length < skip + encrypt length\n");
		return;
	}
	if (length % 8) {
		printf("length is not multiple of 8\n");
		return;
	}

	m = m0;
	off = 0;

	/* skip over the header */
	while (skip) {
		if (!m)
			panic("mbuf chain?\n");
		if (m->m_len <= skip) {
			skip -= m->m_len;
			m = m->m_next;
			off = 0;
		} else {
			off = skip;
			skip = 0;
		}
	}

	/* initialize */
	tin0 = tin1 = tout0 = tout1 = 0;
	tin[0] = tin[1] = 0;

	if (mode == BF_ENCRYPT) {
		u_int8_t *in, *out;

		n2l(iv, tout0);
		n2l(iv, tout1);

		while (0 < length) {
			if (!m)
				panic("mbuf chain?\n");

			/*
			 * copy the source into input buffer.
			 * don't update off or m, since we need to use them				 * later.
			 */
			if (off + 8 <= m->m_len)
				bcopy(mtod(m, u_int8_t *) + off, &inbuf[0], 8);
			else {
				struct mbuf *n;
				size_t noff;
				u_int8_t *p;
				u_int8_t *in;

				n = m;
				noff = off;
				p = mtod(n, u_int8_t *) + noff;

				in = &inbuf[0];
				while (in - &inbuf[0] < 8) {
					if (!p)
						panic("mbuf chain?\n");
					
					*in++ = *p++;
					noff++;
					if (noff < n->m_len)
						continue;
					do {
						n = n->m_next;
					} while (n && ! n->m_len);
					noff = 0;
					if (n)
						p = mtod(n, u_int8_t *) + noff;
					else
						p = NULL;
				}
			}

			in = &inbuf[0];
			out = &outbuf[0];
			n2l(in, tin0);
			n2l(in, tin1);

			tin0 ^= tout0; tin[0] = tin0;
			tin1 ^= tout1; tin[1] = tin1;
			BF_encrypt(tin, key, BF_ENCRYPT);
			tout0 = tin[0]; l2n(tout0, out);
			tout1 = tin[1]; l2n(tout1, out);

			/*
			 * copy the output buffer into the result.
			 * need to update off and m.
			 */
			if (off + 8 < m->m_len) {
				bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
				off += 8;
			} else if (off + 8 == m->m_len) {
				bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
				do {
					m = m->m_next;
				} while (m && ! m->m_len);
				off = 0;
			} else {
				struct mbuf *n;
				size_t noff;
				u_int8_t *p;
				u_int8_t *out;

				n = m;
				noff = off;
				p = mtod(n, u_int8_t *) + noff;

				out = &outbuf[0];
				while (out - &outbuf[0] < 8) {
					if (!p)
						panic("mbuf chain?");
					*p++ = *out++;
					noff++;
					if (noff < n->m_len)
						continue;
					do {
						n = n->m_next;
					} while (n && ! n->m_len);
					noff = 0;
					if (n)
						p = mtod(n, u_int8_t *) + noff;
					else
						p = NULL;
				}

				m = n;
				off = noff;
			}

			length -= 8;
		}
	} else if (mode == BF_DECRYPT) {
		register BF_LONG xor0, xor1;
		u_int8_t *in, *out;

		xor0 = xor1 = 0;
		n2l(iv, xor0);
		n2l(iv, xor1);

		while (0 < length) {
			if (!m)
				panic("mbuf chain?\n");

			/*
			 * copy the source into input buffer.
			 * don't update off or m, since we need to use them				 * later.
			 */
			if (off + 8 <= m->m_len)
				bcopy(mtod(m, u_int8_t *) + off, &inbuf[0], 8);
			else {
				struct mbuf *n;
				size_t noff;
				u_int8_t *p;
				u_int8_t *in;

				n = m;
				noff = off;
				p = mtod(n, u_int8_t *) + noff;

				in = &inbuf[0];
				while (in - &inbuf[0] < 8) {
					if (!p)
						panic("mbuf chain?\n");
					*in++ = *p++;
					noff++;
					if (noff < n->m_len)
						continue;
					do {
						n = n->m_next;
					} while (n && ! n->m_len);
					noff = 0;
					if (n)
						p = mtod(n, u_int8_t *) + noff;
					else
						p = NULL;
				}
			}

			in = &inbuf[0];
			out = &outbuf[0];
			n2l(in, tin0); tin[0] = tin0;
			n2l(in, tin1); tin[1] = tin1;
			BF_encrypt(tin, key, BF_DECRYPT);
			tout0 = tin[0] ^ xor0;
			tout1 = tin[1] ^ xor1;
			l2n(tout0, out);
			l2n(tout1, out);
			xor0 = tin0;
			xor1 = tin1;


			/*
			 * copy the output buffer into the result.
			 * need to update off and m.
			 */
			if (off + 8 < m->m_len) {
				bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
				off += 8;
			} else if (off + 8 == m->m_len) {
				bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
				do {
					m = m->m_next;
				} while (m && ! m->m_len);
				off = 0;
			} else {
				struct mbuf *n;
				size_t noff;
				u_int8_t *p;
				u_int8_t *out;

				n = m;
				noff = off;
				p = mtod(n, u_int8_t *) + noff;

				out = &outbuf[0];
				while (out - &outbuf[0] < 8) {
					if (!p)
						panic("mbuf chain?\n");
					*p++ = *out++;
					noff++;
					if (noff < n->m_len)
						continue;
					do {
						n = n->m_next;
					} while (n && ! n->m_len);
					noff = 0;
					if (n)
						p = mtod(n, u_int8_t *) + noff;
					else
						p = NULL;
				}

				m = n;
				off = noff;
			}

			length -= 8;
		}
	}
}
