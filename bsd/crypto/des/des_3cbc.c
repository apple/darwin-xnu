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
 * based on sys/crypto/des/des_cbc.c, rewrote by Tomomi Suzuki
 */
#include <crypto/des/des_locl.h>


void des_3cbc_process(m0, skip, length, schedule, ivec, mode)
	struct mbuf *m0;
	size_t skip;
	size_t length;
	des_key_schedule *schedule;
	des_cblock (*ivec);
	int mode;
{
	u_int8_t inbuf[8], outbuf[8];
	struct mbuf *m;
	size_t off;
	DES_LONG tin0, tin1;
	DES_LONG tout0, tout1;
	DES_LONG tin[2];
	DES_LONG xor0 = 0, xor1 = 0;
	u_int8_t *iv;
	u_int8_t *in, *out;

	/* sanity check */
	if (m0->m_pkthdr.len < skip) {
		printf("des_3cbc_process: mbuf length < skip\n");
		return;
	}
	if (m0->m_pkthdr.len < length) {
		printf("des_3cbc_process: mbuf length < encrypt length\n");
		return;
	}
	if (m0->m_pkthdr.len < skip + length) {
		printf("des_3cbc_process: mbuf length < "
			"skip + encrypt length\n");
		return;
	}
	if (length % 8) {
		printf("des_3cbc_process: length(%lu) is not multiple of 8\n",
			(u_long)length);
		return;
	}

	m = m0;
	off = 0;

	/* skip over the header */
	while (skip) {
		if (!m)
			panic("des_3cbc_process: mbuf chain?\n");
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

	switch (mode) {
	case DES_ENCRYPT:
		iv = (u_int8_t *)ivec;
		c2l(iv, tout0);
		c2l(iv, tout1);
		break;
	case DES_DECRYPT:
		xor0 = xor1 = 0;
		iv = (u_int8_t *)ivec;
		c2l(iv, xor0);
		c2l(iv, xor1);
		break;
	}

	/*
	 * encrypt/decrypt packet
	 */
	while (length > 0) {
		if (!m)
			panic("des_3cbc_process: mbuf chain?\n");

		/*
		 * copy the source into input buffer.
		 * don't update off or m, since we need to use them
		 * later.
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
				if (!p) {
					panic("des_3cbc_process: "
						"mbuf chain?\n");
				}
				*in++ = *p++;
				noff++;
				if (noff < n->m_len)
					continue;
				do {
					n = n->m_next;
				} while (n && !n->m_len);
				noff = 0;
				if (n)
					p = mtod(n, u_int8_t *) + noff;
				else
					p = NULL;
			}
		}

		/* encrypt/decrypt */
		switch (mode) {
		case DES_ENCRYPT:
			in = &inbuf[0];
			out = &outbuf[0];
			c2l(in, tin0);
			c2l(in, tin1);

			/* XOR */
			tin0 ^= tout0; tin[0] = tin0;
			tin1 ^= tout1; tin[1] = tin1;

			des_encrypt((DES_LONG *)tin, schedule[0], DES_ENCRYPT);
			des_encrypt((DES_LONG *)tin, schedule[1], DES_DECRYPT);
			des_encrypt((DES_LONG *)tin, schedule[2], DES_ENCRYPT);

			tout0 = tin[0]; l2c(tout0, out);
			tout1 = tin[1]; l2c(tout1, out);
			break;
		case DES_DECRYPT:
			in = &inbuf[0];
			out = &outbuf[0];
			c2l(in, tin0); tin[0] = tin0;
			c2l(in, tin1); tin[1] = tin1;

			des_encrypt((DES_LONG *)tin, schedule[2], DES_DECRYPT);
			des_encrypt((DES_LONG *)tin, schedule[1], DES_ENCRYPT);
			des_encrypt((DES_LONG *)tin, schedule[0], DES_DECRYPT);

			/* XOR */
			tout0 = tin[0] ^ xor0;
			tout1 = tin[1] ^ xor1;
			l2c(tout0, out);
			l2c(tout1, out);

			/* for next iv */
			xor0 = tin0;
			xor1 = tin1;
			break;
		}

		/*
		 * copy the output buffer int the result.
		 * need to update off and m.
		 */
		if (off + 8 < m->m_len) {
			bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
			off += 8;
		} else if (off + 8 == m->m_len) {
			bcopy(&outbuf[0], mtod(m, u_int8_t *) + off, 8);
			do {
				m = m->m_next;
			} while (m && !m->m_len);
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
				if (!p) {
					panic("des_3cbc_process: "
						"mbuf chain?\n");
				}
				*p++ = *out++;
				noff++;
				if (noff < n->m_len)
					continue;
				do {
					n = n->m_next;
				} while (n && !n->m_len);
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

