/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_rijndael.c,v 1.1.2.1 2001/07/03 11:01:50 ume Exp $	*/
/*	$KAME: esp_rijndael.c,v 1.4 2001/03/02 05:53:05 itojun Exp $	*/

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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>

#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp_rijndael.h>

#include <libkern/crypto/aes.h>

#include <netkey/key.h>

#include <net/net_osdep.h>

#define MAX_REALIGN_LEN 2000
#define AES_BLOCKLEN 16
#define ESP_GCM_SALT_LEN 4   // RFC 4106 Section 4
#define ESP_GCM_IVLEN 8
#define ESP_GCM_ALIGN 16

extern lck_mtx_t *sadb_mutex;

typedef struct {
        ccgcm_ctx *decrypt;
        ccgcm_ctx *encrypt;
        ccgcm_ctx ctxt[0];
} aes_gcm_ctx;

int
esp_aes_schedlen(
	__unused const struct esp_algorithm *algo)
{

	return sizeof(aes_ctx);
}

int
esp_aes_schedule(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav)
{

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	aes_ctx *ctx = (aes_ctx*)sav->sched;
	
	aes_decrypt_key((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc), &ctx->decrypt);
	aes_encrypt_key((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc), &ctx->encrypt);
	
	return 0;
}


/* The following 2 functions decrypt or encrypt the contents of
 * the mbuf chain passed in keeping the IP and ESP header's in place,
 * along with the IV.
 * The code attempts to call the crypto code with the largest chunk
 * of data it can based on the amount of source data in
 * the current source mbuf and the space remaining in the current
 * destination mbuf.  The crypto code requires data to be a multiples
 * of 16 bytes.  A separate buffer is used when a 16 byte block spans
 * mbufs.
 *
 * m = mbuf chain
 * off = offset to ESP header
 * 
 * local vars for source:
 * soff = offset from beginning of the chain to the head of the
 *			current mbuf.
 * scut = last mbuf that contains headers to be retained
 * scutoff = offset to end of the headers in scut
 * s = the current mbuf
 * sn = current offset to data in s (next source data to process)
 *
 * local vars for dest:
 * d0 = head of chain
 * d = current mbuf
 * dn = current offset in d (next location to store result)
 */
 
 
int
esp_cbc_decrypt_aes(
	struct mbuf *m,
	size_t off,
	struct secasvar *sav,
	const struct esp_algorithm *algo,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;	/* offset from the head of chain, to head of this mbuf */
	int sn, dn;	/* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t iv[AES_BLOCKLEN] __attribute__((aligned(4))), *dptr;
	u_int8_t sbuf[AES_BLOCKLEN] __attribute__((aligned(4))), *sp, *sp_unaligned, *sp_aligned = NULL;
	struct mbuf *scut;
	int scutoff;
	int	i, len;

		
	if (ivlen != AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: bad len %d/%lu\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "payload length must be multiple of %d\n",
		    algo->name, AES_BLOCKLEN));
		m_freem(m);
		return EINVAL;
	}

	/* grab iv */
	m_copydata(m, ivoff, ivlen, (caddr_t) iv);

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;
	
	/* skip header/IV offset */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0)
		s = s->m_next;
	
	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + AES_BLOCKLEN <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
			len = s->m_len - sn;
			len -= len % AES_BLOCKLEN;	// full blocks only
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, AES_BLOCKLEN, (caddr_t) sbuf);
			sp = sbuf;
			len = AES_BLOCKLEN;			// 1 block only in sbuf
		}

		/* destination */
		if (!d || dn + AES_BLOCKLEN > d->m_len) {
			if (d)
				dp = d;
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0)
					m_freem(d0);
				return ENOBUFS;
			}
			if (!d0)
				d0 = d;
			if (dp)
				dp->m_next = d;

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = M_TRAILINGSPACE(d);
			d->m_len -= d->m_len % AES_BLOCKLEN;
			if (d->m_len > i)
				d->m_len = i;
			dptr = mtod(d, u_int8_t *);	
			dn = 0;
		}

		/* adjust len if greater than space available in dest */
		if (len > d->m_len - dn)
			len = d->m_len - dn;

		/* decrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is unaligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)_MALLOC(MAX_REALIGN_LEN, M_SECA, M_DONTWAIT);
				if (sp_aligned == NULL)
					return ENOMEM;
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}
		// no need to check output pointer alignment
		aes_decrypt_cbc(sp, iv, len >> 4, dptr + dn, 
				(aes_decrypt_ctx*)(&(((aes_ctx*)sav->sched)->decrypt)));
		
		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* udpate offsets */
		sn += len;
		dn += len;
		
		// next iv
		bcopy(sp + len - AES_BLOCKLEN, iv, AES_BLOCKLEN);

		/* find the next source block */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}

	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	// free memory
	if (sp_aligned != NULL) {
		FREE(sp_aligned, M_SECA);
		sp_aligned = NULL;
	}
	
	/* just in case */
	bzero(iv, sizeof(iv));
	bzero(sbuf, sizeof(sbuf));

	return 0;
}

int
esp_cbc_encrypt_aes(
	struct mbuf *m,
	size_t off,
	__unused size_t plen,
	struct secasvar *sav,
	const struct esp_algorithm *algo,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;	/* offset from the head of chain, to head of this mbuf */
	int sn, dn;	/* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t *ivp, *dptr, *ivp_unaligned;
	u_int8_t sbuf[AES_BLOCKLEN] __attribute__((aligned(4))), *sp, *sp_unaligned, *sp_aligned = NULL;
	u_int8_t ivp_aligned_buf[AES_BLOCKLEN] __attribute__((aligned(4)));
	struct mbuf *scut;
	int scutoff;
	int i, len;

	if (ivlen != AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	/* put iv into the packet */
	m_copyback(m, ivoff, ivlen, sav->iv);
	ivp = (u_int8_t *) sav->iv;

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: bad len %d/%lu\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % AES_BLOCKLEN) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "payload length must be multiple of %lu\n",
		    algo->name, AES_BLOCKLEN));
		m_freem(m);
		return EINVAL;
	}

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;
	
	/* skip headers/IV */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0)
		s = s->m_next;
	
	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + AES_BLOCKLEN <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
			len = s->m_len - sn;
			len -= len % AES_BLOCKLEN;	// full blocks only
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, AES_BLOCKLEN, (caddr_t) sbuf);
			sp = sbuf;
			len = AES_BLOCKLEN;			// 1 block only in sbuf
		}

		/* destination */
		if (!d || dn + AES_BLOCKLEN > d->m_len) {
			if (d)
				dp = d;
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0)
					m_freem(d0);
				return ENOBUFS;
			}
			if (!d0)
				d0 = d;
			if (dp)
				dp->m_next = d;

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = M_TRAILINGSPACE(d);
			d->m_len -= d->m_len % AES_BLOCKLEN;
			if (d->m_len > i)
				d->m_len = i;
			dptr = mtod(d, u_int8_t *);
			dn = 0;
		}
		
		/* adjust len if greater than space available */
		if (len > d->m_len - dn)
			len = d->m_len - dn;
		
		/* encrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)_MALLOC(MAX_REALIGN_LEN, M_SECA, M_DONTWAIT);
				if (sp_aligned == NULL)
					return ENOMEM;
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}
		// check ivp pointer alignment and use a separate aligned buffer (if ivp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(ivp)) {
			ivp_unaligned = NULL;
		} else {
			ivp_unaligned = ivp;
			ivp = ivp_aligned_buf;
			memcpy(ivp, ivp_unaligned, AES_BLOCKLEN);
		}
		// no need to check output pointer alignment
		aes_encrypt_cbc(sp, ivp, len >> 4, dptr + dn, 
			(aes_encrypt_ctx*)(&(((aes_ctx*)sav->sched)->encrypt)));

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}
		if (!IPSEC_IS_P2ALIGNED(ivp_unaligned)) {
			ivp = ivp_unaligned;
		}

		/* update offsets */
		sn += len;
		dn += len;

		/* next iv */
		ivp = dptr + dn - AES_BLOCKLEN;	// last block encrypted
		
		/* find the next source block and skip empty mbufs */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;
	
	// free memory
	if (sp_aligned != NULL) {
		FREE(sp_aligned, M_SECA);
		sp_aligned = NULL;
	}

	/* just in case */
	bzero(sbuf, sizeof(sbuf));
	key_sa_stir_iv(sav);

	return 0;
}

int
esp_gcm_schedlen(
	__unused const struct esp_algorithm *algo)
{
        return (sizeof(aes_gcm_ctx) + aes_decrypt_get_ctx_size_gcm() + aes_encrypt_get_ctx_size_gcm() + ESP_GCM_ALIGN);
}

int
esp_gcm_schedule( __unused const struct esp_algorithm *algo,
		 struct secasvar *sav)
{
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	int rc;

	ctx->decrypt = &ctx->ctxt[0];
	ctx->encrypt = &ctx->ctxt[aes_decrypt_get_ctx_size_gcm() / sizeof(ccgcm_ctx)];

	rc = aes_decrypt_key_gcm((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc)-ESP_GCM_SALT_LEN, ctx->decrypt);
	if (rc) {
	        return (rc);
	}

	rc = aes_encrypt_key_gcm((const unsigned char *) _KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc)-ESP_GCM_SALT_LEN, ctx->encrypt);
	if (rc) {
	        return (rc);
	}
	return (rc);
}

int
esp_gcm_encrypt_finalize(struct secasvar *sav,
			 unsigned char *tag, unsigned int tag_bytes)
{
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	return (aes_encrypt_finalize_gcm(tag, tag_bytes, ctx->encrypt));
}

int
esp_gcm_decrypt_finalize(struct secasvar *sav,
			 unsigned char *tag, unsigned int tag_bytes)
{
	aes_gcm_ctx *ctx = (aes_gcm_ctx*)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	return (aes_decrypt_finalize_gcm(tag, tag_bytes, ctx->decrypt));
}

int
esp_gcm_encrypt_aes(
	struct mbuf *m,
	size_t off,
	__unused size_t plen,
	struct secasvar *sav,
	const struct esp_algorithm *algo __unused,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;	/* offset from the head of chain, to head of this mbuf */
	int sn, dn;	/* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t *dptr, *sp, *sp_unaligned, *sp_aligned = NULL;
	aes_gcm_ctx *ctx;
	struct mbuf *scut;
	int scutoff;
	int i, len;
	unsigned char nonce[ESP_GCM_SALT_LEN+ivlen];
	
	if (ivlen != ESP_GCM_IVLEN) {
	        ipseclog((LOG_ERR, "%s: unsupported ivlen %d\n", __FUNCTION__, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	m_copyback(m, ivoff, ivlen, sav->iv);

	if (m->m_pkthdr.len < bodyoff) {
	        ipseclog((LOG_ERR, "%s: bad len %d/%lu\n", __FUNCTION__,
		    m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}

	/* Set IV */
	memcpy(nonce, _KEYBUF(sav->key_enc)+_KEYLEN(sav->key_enc)-ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
	memcpy(nonce+ESP_GCM_SALT_LEN, sav->iv, ivlen);

	ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	if (aes_encrypt_set_iv_gcm(nonce, sizeof(nonce), ctx->encrypt)) {
	        ipseclog((LOG_ERR, "%s: failed to set IV\n", __FUNCTION__));
		m_freem(m);
		bzero(nonce, sizeof(nonce));
		return EINVAL;
	}
	bzero(nonce, sizeof(nonce));

	/* Set Additional Authentication Data */
	if (!(sav->flags & SADB_X_EXT_OLD)) {
	        struct newesp esp;
		m_copydata(m, off, sizeof(esp), (caddr_t) &esp);
		if (aes_encrypt_aad_gcm((unsigned char*)&esp, sizeof(esp), ctx->encrypt)) {
		        ipseclog((LOG_ERR, "%s: packet decryption AAD failure\n", __FUNCTION__));
			m_freem(m);
			return EINVAL;
		}
	}

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;
	
	/* skip headers/IV */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0)
		s = s->m_next;
	
	while (soff < m->m_pkthdr.len) {
	        /* source */
	        sp = mtod(s, u_int8_t *) + sn;
		len = s->m_len - sn;

		/* destination */
		if (!d || (dn + len > d->m_len)) {
			if (d)
				dp = d;
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0)
					m_freem(d0);
				return ENOBUFS;
			}
			if (!d0)
				d0 = d;
			if (dp)
				dp->m_next = d;

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = M_TRAILINGSPACE(d);

			if (d->m_len > i)
				d->m_len = i;

			dptr = mtod(d, u_int8_t *);
			dn = 0;
		}
		
		/* adjust len if greater than space available */
		if (len > d->m_len - dn)
			len = d->m_len - dn;
		
		/* encrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)_MALLOC(MAX_REALIGN_LEN, M_SECA, M_DONTWAIT);
				if (sp_aligned == NULL)
					return ENOMEM;
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}

		if (aes_encrypt_gcm(sp, len, dptr+dn, ctx->encrypt)) {
		        ipseclog((LOG_ERR, "%s: failed to encrypt\n", __FUNCTION__));
			m_freem(m);
			return EINVAL;
		}

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* update offsets */
		sn += len;
		dn += len;

		/* find the next source block and skip empty mbufs */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;
	
	// free memory
	if (sp_aligned != NULL) {
		FREE(sp_aligned, M_SECA);
		sp_aligned = NULL;
	}

	/* generate new iv */
	key_sa_stir_iv(sav);

	return 0;
}

int
esp_gcm_decrypt_aes(
	struct mbuf *m,
	size_t off,
	struct secasvar *sav,
	const struct esp_algorithm *algo __unused,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff;	/* offset from the head of chain, to head of this mbuf */
	int sn, dn;	/* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t iv[ESP_GCM_IVLEN] __attribute__((aligned(4))), *dptr;
	u_int8_t *sp, *sp_unaligned, *sp_aligned = NULL;
	aes_gcm_ctx *ctx;
	struct mbuf *scut;
	int scutoff;
	int	i, len;
	unsigned char nonce[ESP_GCM_SALT_LEN+ivlen];

	if (ivlen != ESP_GCM_IVLEN) {
	        ipseclog((LOG_ERR, "%s: unsupported ivlen %d\n", __FUNCTION__, ivlen));
		m_freem(m);
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
	} else {
		ivoff = off + sizeof(struct newesp);
		bodyoff = off + sizeof(struct newesp) + ivlen;
	}

	if (m->m_pkthdr.len < bodyoff) {
	        ipseclog((LOG_ERR, "%s: bad len %d/%lu\n", __FUNCTION__, 
		    m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}

	/* grab iv */
	m_copydata(m, ivoff, ivlen, (caddr_t) iv);

	/* Set IV */
	memcpy(nonce, _KEYBUF(sav->key_enc)+_KEYLEN(sav->key_enc)-ESP_GCM_SALT_LEN, ESP_GCM_SALT_LEN);
	memcpy(nonce+ESP_GCM_SALT_LEN, iv, ivlen);

	ctx = (aes_gcm_ctx *)P2ROUNDUP(sav->sched, ESP_GCM_ALIGN);
	if (aes_decrypt_set_iv_gcm(nonce, sizeof(nonce), ctx->decrypt)) {
	        ipseclog((LOG_ERR, "%s: failed to set IV\n", __FUNCTION__));
		m_freem(m);
		bzero(nonce, sizeof(nonce));
		return EINVAL;
	}
	bzero(nonce, sizeof(nonce));

	/* Set Additional Authentication Data */
	if (!(sav->flags & SADB_X_EXT_OLD)) {
	        struct newesp esp;
		m_copydata(m, off, sizeof(esp), (caddr_t) &esp);
		if (aes_decrypt_aad_gcm((unsigned char*)&esp, sizeof(esp), ctx->decrypt)) {
		        ipseclog((LOG_ERR, "%s: packet decryption AAD failure\n", __FUNCTION__));
			return EINVAL;
		}
	}

	s = m;
	soff = sn = dn = 0;
	d = d0 = dp = NULL;
	sp = dptr = NULL;
	
	/* skip header/IV offset */
	while (soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}
	scut = s;
	scutoff = sn;

	/* skip over empty mbuf */
	while (s && s->m_len == 0)
		s = s->m_next;
	
	while (soff < m->m_pkthdr.len) {
		/* source */
	        sp = mtod(s, u_int8_t *) + sn;
		len = s->m_len - sn;

		/* destination */
		if (!d || (dn + len > d->m_len)) {
			if (d)
				dp = d;
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					d = m_mbigget(d, M_DONTWAIT);
					if ((d->m_flags & M_EXT) == 0) {
						m_free(d);
						d = NULL;
					}
				}
			}
			if (!d) {
				m_freem(m);
				if (d0)
					m_freem(d0);
				return ENOBUFS;
			}
			if (!d0)
				d0 = d;
			if (dp)
				dp->m_next = d;

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = M_TRAILINGSPACE(d);

			if (d->m_len > i)
				d->m_len = i;

			dptr = mtod(d, u_int8_t *);	
			dn = 0;
		}

		/* adjust len if greater than space available in dest */
		if (len > d->m_len - dn)
			len = d->m_len - dn;

		/* Decrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is unaligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			if (len > MAX_REALIGN_LEN) {
				return ENOBUFS;
			}
			if (sp_aligned == NULL) {
				sp_aligned = (u_int8_t *)_MALLOC(MAX_REALIGN_LEN, M_SECA, M_DONTWAIT);
				if (sp_aligned == NULL)
					return ENOMEM;
			}
			sp = sp_aligned;
			memcpy(sp, sp_unaligned, len);
		}
		// no need to check output pointer alignment

		if (aes_decrypt_gcm(sp, len, dptr + dn, ctx->decrypt)) {
		        ipseclog((LOG_ERR, "%s: failed to decrypt\n", __FUNCTION__));
			m_freem(m);
			return EINVAL;
		}
		
		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* udpate offsets */
		sn += len;
		dn += len;
		
		/* find the next source block */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	/* free un-needed source mbufs and add dest mbufs to chain */
	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	// free memory
	if (sp_aligned != NULL) {
		FREE(sp_aligned, M_SECA);
		sp_aligned = NULL;
	}
	
	/* just in case */
	bzero(iv, sizeof(iv));

	return 0;
}
