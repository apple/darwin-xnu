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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <crypto/cast128/cast128.h>


void
cast128_cbc_process(m0, skip, length, subkey, iv, keylen, mode)
	struct mbuf *m0;
	size_t skip;
	size_t length;
	u_int32_t *subkey;
	u_int8_t *iv;
	size_t keylen;
	int mode;
{
	struct mbuf *m;
	u_int8_t inbuf[8], outbuf[8];
	size_t off;

	/* sanity check */
	if (m0->m_pkthdr.len < skip) {
		printf("cast128_cbc_process: mbuf length < skip\n");
		return;
	}
	if (m0->m_pkthdr.len < length) {
		printf("cast128_cbc_process: mbuf length < encrypt length\n");
		return;
	}
	if (m0->m_pkthdr.len < skip + length) {
		printf("cast128_cbc_process: "
			"mbuf length < skip + encrypt length\n");
		return;
	}
	if (length % 8) {
		printf("cast128_cbc_process: length is not multiple of 8\n");
		return;
	}

	m = m0;
	off = 0;

	/* skip over the header */
	while (skip) {
		if (!m)
			panic("cast128_cbc_process: mbuf chain?\n");
		if (m->m_len <= skip) {
			skip -= m->m_len;
			m = m->m_next;
			off = 0;
		} else {
			off = skip;
			skip = 0;
		}
	}

	/* copy iv into outbuf for XOR (encrypt) */
	bcopy(iv, outbuf, 8);

	/*
	 * encrypt/decrypt packet
	 */
	while (length > 0) {
		int i;

		if (!m)
			panic("cast128_cbc_process: mbuf chain?\n");

		/*
		 * copy the source into input buffer.
		 * don't update off or m, since we need to use them
		 * later.
		 */
		if (off + 8 <= m->m_len)
			bcopy(mtod(m, u_int8_t *)+off, inbuf, 8);
		else {
			struct mbuf *n;
			size_t noff;
			u_int8_t *p, *in;

			n = m;
			noff = off;
			p = mtod(n, u_int8_t *) + noff;

			in = inbuf;
			while (in - inbuf < 8) {
				if (!p) {
					panic("cast128_cbc_process: "
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
					p = mtod(n, u_int8_t *);
				else
					p = NULL;
			}
		}

		/* encrypt/decrypt */
		switch (mode) {
		case CAST128_ENCRYPT:
			/* XOR */
			for (i = 0; i < 8; i++)
				inbuf[i] ^= outbuf[i];

			/* encrypt */
			if (keylen <= 80/8)
				cast128_encrypt_round12(outbuf, inbuf, subkey);
			else
				cast128_encrypt_round16(outbuf, inbuf, subkey);
			break;

		case CAST128_DECRYPT:
			/* decrypt */
			if (keylen <= 80/8)
				cast128_decrypt_round12(outbuf, inbuf, subkey);
			else
				cast128_decrypt_round16(outbuf, inbuf, subkey);

			/* XOR */
			for (i = 0; i < 8; i++)
				outbuf[i] ^= iv[i];

			/* copy inbuf into iv for next XOR */
			bcopy(inbuf, iv, 8);
			break;
		}

		/*
		 * copy the output buffer into the result.
		 * need to update off and m.
		 */
		if (off + 8 < m->m_len) {
			bcopy(outbuf, mtod(m, u_int8_t *) + off, 8);
			off += 8;
		} else if (off + 8 == m->m_len) {
			bcopy(outbuf, mtod(m, u_int8_t *) + off, 8);
			do {
				m = m->m_next;
			} while (m && !m->m_len);
			off = 0;
		} else {
			struct mbuf *n;
			size_t noff;
			u_int8_t *p, *out;

			n = m;
			noff = off;
			p = mtod(n, u_int8_t *) + noff;

			out = outbuf;
			while (out - outbuf < 8) {
				if (!p) {
					panic("cast128_cbc_process: "
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
					p = mtod(n, u_int8_t *);
				else
					p = NULL;
			}

			m = n;
			off = noff;
		}

		length -= 8;
	}
}

