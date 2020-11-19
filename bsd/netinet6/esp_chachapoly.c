/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <mach/vm_param.h>
#include <kern/locks.h>
#include <string.h>
#include <net/if.h>
#include <net/route.h>
#include <net/net_osdep.h>
#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp_chachapoly.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <corecrypto/cc.h>
#include <libkern/crypto/chacha20poly1305.h>

#define ESP_CHACHAPOLY_SALT_LEN         4
#define ESP_CHACHAPOLY_KEY_LEN          32
#define ESP_CHACHAPOLY_NONCE_LEN        12

// The minimum alignment is documented in KALLOC_LOG2_MINALIGN
// which isn't accessible from here. Current minimum is 8.
_Static_assert(_Alignof(chacha20poly1305_ctx) <= 8,
    "Alignment guarantee is broken");

#if (((8 * (ESP_CHACHAPOLY_KEY_LEN + ESP_CHACHAPOLY_SALT_LEN)) != ESP_CHACHAPOLY_KEYBITS_WITH_SALT) || \
        (ESP_CHACHAPOLY_KEY_LEN != CCCHACHA20_KEY_NBYTES) || \
        (ESP_CHACHAPOLY_NONCE_LEN != CCCHACHA20POLY1305_NONCE_NBYTES))
#error "Invalid sizes"
#endif

extern lck_mtx_t *sadb_mutex;

typedef struct _esp_chachapoly_ctx {
	chacha20poly1305_ctx ccp_ctx;
	uint8_t ccp_salt[ESP_CHACHAPOLY_SALT_LEN];
	bool ccp_implicit_iv;
} esp_chachapoly_ctx_s, *esp_chachapoly_ctx_t;


#define ESP_ASSERT(_cond, _format, ...)                                                                                 \
	do {                                                                                                                                            \
	        if (!(_cond)) {                                                                                                                 \
	                panic("%s:%d " _format, __FUNCTION__, __LINE__, ##__VA_ARGS__);         \
	        }                                                                                                                                               \
	} while (0)

#define ESP_CHECK_ARG(_arg) ESP_ASSERT(_arg != NULL, #_arg " is NULL")

#define _esp_log(_level, _format, ...)  \
	log(_level, "%s:%d " _format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define esp_log_err(_format, ...) _esp_log(LOG_ERR, _format, ##__VA_ARGS__)
#define esp_log_default(_format, ...) _esp_log(LOG_NOTICE, _format, ##__VA_ARGS__)

#define _esp_packet_log(_level, _format, ...)  \
	ipseclog((_level, "%s:%d " _format, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define esp_packet_log_err(_format, ...) _esp_packet_log(LOG_ERR, _format, ##__VA_ARGS__)

int
esp_chachapoly_mature(struct secasvar *sav)
{
	const struct esp_algorithm *algo;

	ESP_CHECK_ARG(sav);

	if ((sav->flags & SADB_X_EXT_OLD) != 0) {
		esp_log_err("ChaChaPoly is incompatible with SADB_X_EXT_OLD, SPI 0x%08x",
		    ntohl(sav->spi));
		return 1;
	}
	if ((sav->flags & SADB_X_EXT_DERIV) != 0) {
		esp_log_err("ChaChaPoly is incompatible with SADB_X_EXT_DERIV, SPI 0x%08x",
		    ntohl(sav->spi));
		return 1;
	}

	if (sav->alg_enc != SADB_X_EALG_CHACHA20POLY1305) {
		esp_log_err("ChaChaPoly unsupported algorithm %d, SPI 0x%08x",
		    sav->alg_enc, ntohl(sav->spi));
		return 1;
	}

	if (sav->key_enc == NULL) {
		esp_log_err("ChaChaPoly key is missing, SPI 0x%08x",
		    ntohl(sav->spi));
		return 1;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (algo == NULL) {
		esp_log_err("ChaChaPoly lookup failed for algorithm %d, SPI 0x%08x",
		    sav->alg_enc, ntohl(sav->spi));
		return 1;
	}

	if (sav->key_enc->sadb_key_bits != ESP_CHACHAPOLY_KEYBITS_WITH_SALT) {
		esp_log_err("ChaChaPoly invalid key length %d bits, SPI 0x%08x",
		    sav->key_enc->sadb_key_bits, ntohl(sav->spi));
		return 1;
	}

	esp_log_default("ChaChaPoly Mature SPI 0x%08x%s %s dir %u state %u mode %u",
	    ntohl(sav->spi),
	    (((sav->flags & SADB_X_EXT_IIV) != 0) ? " IIV" : ""),
	    ((sav->sah->ipsec_if != NULL) ? if_name(sav->sah->ipsec_if) : "NONE"),
	    sav->sah->dir, sav->sah->state, sav->sah->saidx.mode);

	return 0;
}

size_t
esp_chachapoly_schedlen(__unused const struct esp_algorithm *algo)
{
	return sizeof(esp_chachapoly_ctx_s);
}

int
esp_chachapoly_schedule(__unused const struct esp_algorithm *algo,
    struct secasvar *sav)
{
	esp_chachapoly_ctx_t esp_ccp_ctx;
	int rc = 0;

	ESP_CHECK_ARG(sav);
	if (_KEYLEN(sav->key_enc) != ESP_CHACHAPOLY_KEY_LEN + ESP_CHACHAPOLY_SALT_LEN) {
		esp_log_err("ChaChaPoly Invalid key len %u, SPI 0x%08x",
		    _KEYLEN(sav->key_enc), ntohl(sav->spi));
		return EINVAL;
	}
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	esp_ccp_ctx = (esp_chachapoly_ctx_t)sav->sched;
	esp_ccp_ctx->ccp_implicit_iv = ((sav->flags & SADB_X_EXT_IIV) != 0);

	if (sav->ivlen != (esp_ccp_ctx->ccp_implicit_iv ? 0 : ESP_CHACHAPOLY_IV_LEN)) {
		esp_log_err("ChaChaPoly Invalid ivlen %u, SPI 0x%08x",
		    sav->ivlen, ntohl(sav->spi));
		return EINVAL;
	}

	rc = chacha20poly1305_init(&esp_ccp_ctx->ccp_ctx,
	    (const uint8_t *)_KEYBUF(sav->key_enc));
	if (rc != 0) {
		esp_log_err("ChaChaPoly chacha20poly1305_init failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	memcpy(esp_ccp_ctx->ccp_salt,
	    (const uint8_t *)_KEYBUF(sav->key_enc) + ESP_CHACHAPOLY_KEY_LEN,
	    sizeof(esp_ccp_ctx->ccp_salt));


	esp_log_default("ChaChaPoly Schedule SPI 0x%08x%s %s dir %u state %u mode %u",
	    ntohl(sav->spi), (esp_ccp_ctx->ccp_implicit_iv ? " IIV" : ""),
	    ((sav->sah->ipsec_if != NULL) ? if_name(sav->sah->ipsec_if) : "NONE"),
	    sav->sah->dir, sav->sah->state, sav->sah->saidx.mode);

	return 0;
}

int
esp_chachapoly_ivlen(const struct esp_algorithm *algo,
    struct secasvar *sav)
{
	ESP_CHECK_ARG(algo);

	if (sav != NULL &&
	    ((sav->sched != NULL && ((esp_chachapoly_ctx_t)sav->sched)->ccp_implicit_iv) ||
	    ((sav->flags & SADB_X_EXT_IIV) != 0))) {
		return 0;
	} else {
		return algo->ivlenval;
	}
}

int
esp_chachapoly_encrypt_finalize(struct secasvar *sav,
    unsigned char *tag,
    size_t tag_bytes)
{
	esp_chachapoly_ctx_t esp_ccp_ctx;
	int rc = 0;

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(tag);
	if (tag_bytes != ESP_CHACHAPOLY_ICV_LEN) {
		esp_log_err("ChaChaPoly Invalid tag_bytes %zu, SPI 0x%08x",
		    tag_bytes, ntohl(sav->spi));
		return EINVAL;
	}

	esp_ccp_ctx = (esp_chachapoly_ctx_t)sav->sched;
	rc = chacha20poly1305_finalize(&esp_ccp_ctx->ccp_ctx, tag);
	if (rc != 0) {
		esp_log_err("ChaChaPoly chacha20poly1305_finalize failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}
	return 0;
}

int
esp_chachapoly_decrypt_finalize(struct secasvar *sav,
    unsigned char *tag,
    size_t tag_bytes)
{
	esp_chachapoly_ctx_t esp_ccp_ctx;
	int rc = 0;

	ESP_CHECK_ARG(sav);
	ESP_CHECK_ARG(tag);
	if (tag_bytes != ESP_CHACHAPOLY_ICV_LEN) {
		esp_log_err("ChaChaPoly Invalid tag_bytes %zu, SPI 0x%08x",
		    tag_bytes, ntohl(sav->spi));
		return EINVAL;
	}

	esp_ccp_ctx = (esp_chachapoly_ctx_t)sav->sched;
	rc = chacha20poly1305_verify(&esp_ccp_ctx->ccp_ctx, tag);
	if (rc != 0) {
		esp_packet_log_err("ChaChaPoly chacha20poly1305_verify failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}
	return 0;
}

int
esp_chachapoly_encrypt(struct mbuf *m, // head of mbuf chain
    size_t off,                                        // offset to ESP header
    __unused size_t plen,
    struct secasvar *sav,
    __unused const struct esp_algorithm *algo,
    int ivlen)
{
	struct mbuf *s = m; // this mbuf
	int32_t soff = 0; // offset from the head of mbuf chain (m) to head of this mbuf (s)
	int32_t sn = 0; // offset from the head of this mbuf (s) to the body
	uint8_t *sp; // buffer of a given encryption round
	size_t len; // length of a given encryption round
	const int32_t ivoff = (int32_t)off + (int32_t)sizeof(struct newesp); // IV offset
	const size_t bodyoff = ivoff + ivlen; // body offset
	int rc = 0; // return code of corecrypto operations
	struct newesp esp_hdr; // ESP header for AAD
	_Static_assert(sizeof(esp_hdr) == 8, "Bad size");
	uint32_t nonce[ESP_CHACHAPOLY_NONCE_LEN / 4]; // ensure 32bit alignment
	_Static_assert(sizeof(nonce) == ESP_CHACHAPOLY_NONCE_LEN, "Bad nonce length");
	esp_chachapoly_ctx_t esp_ccp_ctx;

	ESP_CHECK_ARG(m);
	ESP_CHECK_ARG(sav);

	esp_ccp_ctx = (esp_chachapoly_ctx_t)sav->sched;

	if (ivlen != (esp_ccp_ctx->ccp_implicit_iv ? 0 : ESP_CHACHAPOLY_IV_LEN)) {
		m_freem(m);
		esp_log_err("ChaChaPoly Invalid ivlen %u, SPI 0x%08x",
		    ivlen, ntohl(sav->spi));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		m_freem(m);
		esp_log_err("ChaChaPoly Invalid sav->ivlen %u, SPI 0x%08x",
		    sav->ivlen, ntohl(sav->spi));
		return EINVAL;
	}

	// check if total packet length is enough to contain ESP + IV
	if (m->m_pkthdr.len < bodyoff) {
		esp_log_err("ChaChaPoly Packet too short %d < %zu, SPI 0x%08x",
		    m->m_pkthdr.len, bodyoff, ntohl(sav->spi));
		m_freem(m);
		return EINVAL;
	}

	rc = chacha20poly1305_reset(&esp_ccp_ctx->ccp_ctx);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_reset failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	// esp_hdr is used for nonce and AAD
	m_copydata(m, (int)off, sizeof(esp_hdr), (void *)&esp_hdr);

	// RFC 7634 dictates that the 12 byte nonce must be
	// the 4 byte salt followed by the 8 byte IV.
	// The IV MUST be non-repeating but does not need to be unpredictable,
	// so we use 4 bytes of 0 followed by the 4 byte ESP sequence number.
	// this allows us to use implicit IV -- draft-ietf-ipsecme-implicit-iv
	// Note that sav->seq is zero here so we must get esp_seq from esp_hdr
	memcpy(nonce, esp_ccp_ctx->ccp_salt, ESP_CHACHAPOLY_SALT_LEN);
	memset(((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN, 0, 4);
	memcpy(((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN + 4,
	    &esp_hdr.esp_seq, sizeof(esp_hdr.esp_seq));

	_Static_assert(4 + sizeof(esp_hdr.esp_seq) == ESP_CHACHAPOLY_IV_LEN,
	    "Bad IV length");
	_Static_assert(ESP_CHACHAPOLY_SALT_LEN + ESP_CHACHAPOLY_IV_LEN == sizeof(nonce),
	    "Bad nonce length");

	rc = chacha20poly1305_setnonce(&esp_ccp_ctx->ccp_ctx, (uint8_t *)nonce);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_setnonce failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	if (!esp_ccp_ctx->ccp_implicit_iv) {
		memcpy(sav->iv, ((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN, ESP_CHACHAPOLY_IV_LEN);
		m_copyback(m, ivoff, ivlen, sav->iv);
	}
	cc_clear(sizeof(nonce), nonce);

	// Set Additional Authentication Data (AAD)
	rc = chacha20poly1305_aad(&esp_ccp_ctx->ccp_ctx,
	    sizeof(esp_hdr),
	    (void *)&esp_hdr);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_aad failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	// skip headers/IV
	while (s != NULL && soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}

	while (s != NULL && soff < m->m_pkthdr.len) {
		len = (size_t)(s->m_len - sn);
		if (len == 0) {
			// skip empty mbufs
			continue;
		}
		sp = mtod(s, uint8_t *) + sn;

		rc = chacha20poly1305_encrypt(&esp_ccp_ctx->ccp_ctx,
		    len, sp, sp);
		if (rc != 0) {
			m_freem(m);
			esp_log_err("ChaChaPoly chacha20poly1305_encrypt failed %d, SPI 0x%08x",
			    rc, ntohl(sav->spi));
			return rc;
		}

		sn = 0;
		soff += s->m_len;
		s = s->m_next;
	}
	if (s == NULL && soff != m->m_pkthdr.len) {
		m_freem(m);
		esp_log_err("ChaChaPoly not enough mbufs %d %d, SPI 0x%08x",
		    soff, m->m_pkthdr.len, ntohl(sav->spi));
		return EFBIG;
	}
	return 0;
}

int
esp_chachapoly_decrypt(struct mbuf *m, // head of mbuf chain
    size_t off,                                        // offset to ESP header
    struct secasvar *sav,
    __unused const struct esp_algorithm *algo,
    int ivlen)
{
	struct mbuf *s = m; // this mbuf
	int32_t soff = 0; // offset from the head of mbuf chain (m) to head of this mbuf (s)
	int32_t sn = 0; // offset from the head of this mbuf (s) to the body
	uint8_t *sp; // buffer of a given encryption round
	size_t len; // length of a given encryption round
	const int32_t ivoff = (int32_t)off + (int32_t)sizeof(struct newesp); // IV offset
	const int32_t bodyoff = ivoff + ivlen; // body offset
	int rc = 0; // return code of corecrypto operations
	struct newesp esp_hdr; // ESP header for AAD
	_Static_assert(sizeof(esp_hdr) == 8, "Bad size");
	uint32_t nonce[ESP_CHACHAPOLY_NONCE_LEN / 4]; // ensure 32bit alignment
	_Static_assert(sizeof(nonce) == ESP_CHACHAPOLY_NONCE_LEN, "Bad nonce length");
	esp_chachapoly_ctx_t esp_ccp_ctx;

	ESP_CHECK_ARG(m);
	ESP_CHECK_ARG(sav);

	esp_ccp_ctx = (esp_chachapoly_ctx_t)sav->sched;

	if (ivlen != (esp_ccp_ctx->ccp_implicit_iv ? 0 : ESP_CHACHAPOLY_IV_LEN)) {
		m_freem(m);
		esp_log_err("ChaChaPoly Invalid ivlen %u, SPI 0x%08x",
		    ivlen, ntohl(sav->spi));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		m_freem(m);
		esp_log_err("ChaChaPoly Invalid sav->ivlen %u, SPI 0x%08x",
		    sav->ivlen, ntohl(sav->spi));
		return EINVAL;
	}

	// check if total packet length is enough to contain ESP + IV
	if (m->m_pkthdr.len < bodyoff) {
		esp_packet_log_err("ChaChaPoly Packet too short %d < %u, SPI 0x%08x",
		    m->m_pkthdr.len, bodyoff, ntohl(sav->spi));
		m_freem(m);
		return EINVAL;
	}

	rc = chacha20poly1305_reset(&esp_ccp_ctx->ccp_ctx);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_reset failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	m_copydata(m, (int)off, sizeof(esp_hdr), (void *)&esp_hdr);

	// RFC 7634 dictates that the 12 byte nonce must be
	// the 4 byte salt followed by the 8 byte IV.
	memcpy(nonce, esp_ccp_ctx->ccp_salt, ESP_CHACHAPOLY_SALT_LEN);
	if (esp_ccp_ctx->ccp_implicit_iv) {
		// IV is implicit (4 zero bytes followed by the ESP sequence number)
		memset(((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN, 0, 4);
		memcpy(((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN + 4,
		    &esp_hdr.esp_seq, sizeof(esp_hdr.esp_seq));
		_Static_assert(4 + sizeof(esp_hdr.esp_seq) == ESP_CHACHAPOLY_IV_LEN, "Bad IV length");
	} else {
		// copy IV from packet
		m_copydata(m, ivoff, ESP_CHACHAPOLY_IV_LEN, ((uint8_t *)nonce) + ESP_CHACHAPOLY_SALT_LEN);
	}
	_Static_assert(ESP_CHACHAPOLY_SALT_LEN + ESP_CHACHAPOLY_IV_LEN == sizeof(nonce),
	    "Bad nonce length");

	rc = chacha20poly1305_setnonce(&esp_ccp_ctx->ccp_ctx, (uint8_t *)nonce);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_setnonce failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}
	cc_clear(sizeof(nonce), nonce);

	// Set Additional Authentication Data (AAD)
	rc = chacha20poly1305_aad(&esp_ccp_ctx->ccp_ctx,
	    sizeof(esp_hdr),
	    (void *)&esp_hdr);
	if (rc != 0) {
		m_freem(m);
		esp_log_err("ChaChaPoly chacha20poly1305_aad failed %d, SPI 0x%08x",
		    rc, ntohl(sav->spi));
		return rc;
	}

	// skip headers/IV
	while (s != NULL && soff < bodyoff) {
		if (soff + s->m_len > bodyoff) {
			sn = bodyoff - soff;
			break;
		}

		soff += s->m_len;
		s = s->m_next;
	}

	while (s != NULL && soff < m->m_pkthdr.len) {
		len = (size_t)(s->m_len - sn);
		if (len == 0) {
			// skip empty mbufs
			continue;
		}
		sp = mtod(s, uint8_t *) + sn;

		rc = chacha20poly1305_decrypt(&esp_ccp_ctx->ccp_ctx,
		    len, sp, sp);
		if (rc != 0) {
			m_freem(m);
			esp_packet_log_err("chacha20poly1305_decrypt failed %d, SPI 0x%08x",
			    rc, ntohl(sav->spi));
			return rc;
		}

		sn = 0;
		soff += s->m_len;
		s = s->m_next;
	}
	if (s == NULL && soff != m->m_pkthdr.len) {
		m_freem(m);
		esp_packet_log_err("not enough mbufs %d %d, SPI 0x%08x",
		    soff, m->m_pkthdr.len, ntohl(sav->spi));
		return EFBIG;
	}
	return 0;
}
