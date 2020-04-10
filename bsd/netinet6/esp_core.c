/*
 * Copyright (c) 2008-2019 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_core.c,v 1.1.2.4 2002/03/26 10:12:29 ume Exp $	*/
/*	$KAME: esp_core.c,v 1.50 2000/11/02 12:27:38 itojun Exp $	*/

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

#define _IP_VHL

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#endif

#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#include <netinet6/esp_rijndael.h>
#include <netinet6/esp_chachapoly.h>
#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <libkern/crypto/des.h>

#include <net/net_osdep.h>

#include <sys/kdebug.h>
#define DBG_LAYER_BEG           NETDBG_CODE(DBG_NETIPSEC, 1)
#define DBG_LAYER_END           NETDBG_CODE(DBG_NETIPSEC, 3)
#define DBG_FNC_ESPAUTH         NETDBG_CODE(DBG_NETIPSEC, (8 << 8))
#define MAX_SBUF_LEN            2000

extern lck_mtx_t *sadb_mutex;
os_log_t esp_mpkl_log_object = NULL;

static int esp_null_mature(struct secasvar *);
static int esp_null_decrypt(struct mbuf *, size_t,
    struct secasvar *, const struct esp_algorithm *, int);
static int esp_null_encrypt(struct mbuf *, size_t, size_t,
    struct secasvar *, const struct esp_algorithm *, int);
static int esp_descbc_mature(struct secasvar *);
static int esp_descbc_ivlen(const struct esp_algorithm *,
    struct secasvar *);
static int esp_des_schedule(const struct esp_algorithm *,
    struct secasvar *);
static int esp_des_schedlen(const struct esp_algorithm *);
static int esp_des_blockdecrypt(const struct esp_algorithm *,
    struct secasvar *, u_int8_t *, u_int8_t *);
static int esp_des_blockencrypt(const struct esp_algorithm *,
    struct secasvar *, u_int8_t *, u_int8_t *);
static int esp_cbc_mature(struct secasvar *);
static int esp_3des_schedule(const struct esp_algorithm *,
    struct secasvar *);
static int esp_3des_schedlen(const struct esp_algorithm *);
static int esp_3des_blockdecrypt(const struct esp_algorithm *,
    struct secasvar *, u_int8_t *, u_int8_t *);
static int esp_3des_blockencrypt(const struct esp_algorithm *,
    struct secasvar *, u_int8_t *, u_int8_t *);
static int esp_common_ivlen(const struct esp_algorithm *,
    struct secasvar *);
static int esp_cbc_decrypt(struct mbuf *, size_t,
    struct secasvar *, const struct esp_algorithm *, int);
static int esp_cbc_encrypt(struct mbuf *, size_t, size_t,
    struct secasvar *, const struct esp_algorithm *, int);
static int esp_gcm_mature(struct secasvar *);

#define MAXIVLEN        16

#define ESP_AESGCM_KEYLEN128 160 // 16-bytes key + 4 bytes salt
#define ESP_AESGCM_KEYLEN192 224 // 24-bytes key + 4 bytes salt
#define ESP_AESGCM_KEYLEN256 288 // 32-bytes key + 4 bytes salt

static const struct esp_algorithm des_cbc = {
	.padbound = 8,
	.ivlenval = -1,
	.mature = esp_descbc_mature,
	.keymin = 64,
	.keymax = 64,
	.schedlen = esp_des_schedlen,
	.name = "des-cbc",
	.ivlen = esp_descbc_ivlen,
	.decrypt = esp_cbc_decrypt,
	.encrypt = esp_cbc_encrypt,
	.schedule = esp_des_schedule,
	.blockdecrypt = esp_des_blockdecrypt,
	.blockencrypt = esp_des_blockencrypt,
	.icvlen = 0,
	.finalizedecrypt = NULL,
	.finalizeencrypt = NULL
};

static const struct esp_algorithm des3_cbc = {
	.padbound = 8,
	.ivlenval = 8,
	.mature = esp_cbc_mature,
	.keymin = 192,
	.keymax = 192,
	.schedlen = esp_3des_schedlen,
	.name = "3des-cbc",
	.ivlen = esp_common_ivlen,
	.decrypt = esp_cbc_decrypt,
	.encrypt = esp_cbc_encrypt,
	.schedule = esp_3des_schedule,
	.blockdecrypt = esp_3des_blockdecrypt,
	.blockencrypt = esp_3des_blockencrypt,
	.icvlen = 0,
	.finalizedecrypt = NULL,
	.finalizeencrypt = NULL
};

static const struct esp_algorithm null_esp = {
	.padbound = 1,
	.ivlenval = 0,
	.mature = esp_null_mature,
	.keymin = 0,
	.keymax = 2048,
	.schedlen = NULL,
	.name = "null",
	.ivlen = esp_common_ivlen,
	.decrypt = esp_null_decrypt,
	.encrypt = esp_null_encrypt,
	.schedule = NULL,
	.blockdecrypt = NULL,
	.blockencrypt = NULL,
	.icvlen = 0,
	.finalizedecrypt = NULL,
	.finalizeencrypt = NULL
};

static const struct esp_algorithm aes_cbc = {
	.padbound = 16,
	.ivlenval = 16,
	.mature = esp_cbc_mature,
	.keymin = 128,
	.keymax = 256,
	.schedlen = esp_aes_schedlen,
	.name = "aes-cbc",
	.ivlen = esp_common_ivlen,
	.decrypt = esp_cbc_decrypt_aes,
	.encrypt = esp_cbc_encrypt_aes,
	.schedule = esp_aes_schedule,
	.blockdecrypt = NULL,
	.blockencrypt = NULL,
	.icvlen = 0,
	.finalizedecrypt = NULL,
	.finalizeencrypt = NULL
};

static const struct esp_algorithm aes_gcm = {
	.padbound = 4,
	.ivlenval = 8,
	.mature = esp_gcm_mature,
	.keymin = ESP_AESGCM_KEYLEN128,
	.keymax = ESP_AESGCM_KEYLEN256,
	.schedlen = esp_gcm_schedlen,
	.name = "aes-gcm",
	.ivlen = esp_common_ivlen,
	.decrypt = esp_gcm_decrypt_aes,
	.encrypt = esp_gcm_encrypt_aes,
	.schedule = esp_gcm_schedule,
	.blockdecrypt = NULL,
	.blockencrypt = NULL,
	.icvlen = 16,
	.finalizedecrypt = esp_gcm_decrypt_finalize,
	.finalizeencrypt = esp_gcm_encrypt_finalize
};

static const struct esp_algorithm chacha_poly = {
	.padbound = ESP_CHACHAPOLY_PAD_BOUND,
	.ivlenval = ESP_CHACHAPOLY_IV_LEN,
	.mature = esp_chachapoly_mature,
	.keymin = ESP_CHACHAPOLY_KEYBITS_WITH_SALT,
	.keymax = ESP_CHACHAPOLY_KEYBITS_WITH_SALT,
	.schedlen = esp_chachapoly_schedlen,
	.name = "chacha-poly",
	.ivlen = esp_chachapoly_ivlen,
	.decrypt = esp_chachapoly_decrypt,
	.encrypt = esp_chachapoly_encrypt,
	.schedule = esp_chachapoly_schedule,
	.blockdecrypt = NULL,
	.blockencrypt = NULL,
	.icvlen = ESP_CHACHAPOLY_ICV_LEN,
	.finalizedecrypt = esp_chachapoly_decrypt_finalize,
	.finalizeencrypt = esp_chachapoly_encrypt_finalize
};

static const struct esp_algorithm *esp_algorithms[] = {
	&des_cbc,
	&des3_cbc,
	&null_esp,
	&aes_cbc,
	&aes_gcm,
	&chacha_poly,
};

const struct esp_algorithm *
esp_algorithm_lookup(int idx)
{
	switch (idx) {
	case SADB_EALG_DESCBC:
		return &des_cbc;
	case SADB_EALG_3DESCBC:
		return &des3_cbc;
	case SADB_EALG_NULL:
		return &null_esp;
	case SADB_X_EALG_RIJNDAELCBC:
		return &aes_cbc;
	case SADB_X_EALG_AES_GCM:
		return &aes_gcm;
	case SADB_X_EALG_CHACHA20POLY1305:
		return &chacha_poly;
	default:
		return NULL;
	}
}

int
esp_max_ivlen(void)
{
	int idx;
	int ivlen;

	ivlen = 0;
	for (idx = 0; idx < sizeof(esp_algorithms) / sizeof(esp_algorithms[0]);
	    idx++) {
		if (esp_algorithms[idx]->ivlenval > ivlen) {
			ivlen = esp_algorithms[idx]->ivlenval;
		}
	}

	return ivlen;
}

int
esp_schedule(const struct esp_algorithm *algo, struct secasvar *sav)
{
	int error;

	/* check for key length */
	if (_KEYBITS(sav->key_enc) < algo->keymin ||
	    _KEYBITS(sav->key_enc) > algo->keymax) {
		ipseclog((LOG_ERR,
		    "esp_schedule %s: unsupported key length %d: "
		    "needs %d to %d bits\n", algo->name, _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}

	lck_mtx_lock(sadb_mutex);
	/* already allocated */
	if (sav->sched && sav->schedlen != 0) {
		lck_mtx_unlock(sadb_mutex);
		return 0;
	}

	/* prevent disallowed implicit IV */
	if (((sav->flags & SADB_X_EXT_IIV) != 0) &&
	    (sav->alg_enc != SADB_X_EALG_AES_GCM) &&
	    (sav->alg_enc != SADB_X_EALG_CHACHA20POLY1305)) {
		ipseclog((LOG_ERR,
		    "esp_schedule %s: implicit IV not allowed\n",
		    algo->name));
		lck_mtx_unlock(sadb_mutex);
		return EINVAL;
	}

	/* no schedule necessary */
	if (!algo->schedule || !algo->schedlen) {
		lck_mtx_unlock(sadb_mutex);
		return 0;
	}

	sav->schedlen = (*algo->schedlen)(algo);
	if ((signed) sav->schedlen < 0) {
		lck_mtx_unlock(sadb_mutex);
		return EINVAL;
	}

//#### that malloc should be replaced by a saved buffer...
	sav->sched = _MALLOC(sav->schedlen, M_SECA, M_DONTWAIT);
	if (!sav->sched) {
		sav->schedlen = 0;
		lck_mtx_unlock(sadb_mutex);
		return ENOBUFS;
	}

	error = (*algo->schedule)(algo, sav);
	if (error) {
		ipseclog((LOG_ERR, "esp_schedule %s: error %d\n",
		    algo->name, error));
		bzero(sav->sched, sav->schedlen);
		FREE(sav->sched, M_SECA);
		sav->sched = NULL;
		sav->schedlen = 0;
	}
	lck_mtx_unlock(sadb_mutex);
	return error;
}

static int
esp_null_mature(
	__unused struct secasvar *sav)
{
	/* anything is okay */
	return 0;
}

static int
esp_null_decrypt(
	__unused struct mbuf *m,
	__unused size_t off,            /* offset to ESP header */
	__unused struct secasvar *sav,
	__unused const struct esp_algorithm *algo,
	__unused int ivlen)
{
	return 0; /* do nothing */
}

static int
esp_null_encrypt(
	__unused struct mbuf *m,
	__unused size_t off,    /* offset to ESP header */
	__unused size_t plen,   /* payload length (to be encrypted) */
	__unused struct secasvar *sav,
	__unused const struct esp_algorithm *algo,
	__unused int ivlen)
{
	return 0; /* do nothing */
}

static int
esp_descbc_mature(struct secasvar *sav)
{
	const struct esp_algorithm *algo;

	if (!(sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_IV4B)) {
		ipseclog((LOG_ERR, "esp_cbc_mature: "
		    "algorithm incompatible with 4 octets IV length\n"));
		return 1;
	}

	if (!sav->key_enc) {
		ipseclog((LOG_ERR, "esp_descbc_mature: no key is given.\n"));
		return 1;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_ERR,
		    "esp_descbc_mature: unsupported algorithm.\n"));
		return 1;
	}

	if (_KEYBITS(sav->key_enc) < algo->keymin ||
	    _KEYBITS(sav->key_enc) > algo->keymax) {
		ipseclog((LOG_ERR,
		    "esp_descbc_mature: invalid key length %d.\n",
		    _KEYBITS(sav->key_enc)));
		return 1;
	}

	/* weak key check */
	if (des_is_weak_key((des_cblock *)_KEYBUF(sav->key_enc))) {
		ipseclog((LOG_ERR,
		    "esp_descbc_mature: weak key was passed.\n"));
		return 1;
	}

	return 0;
}

static int
esp_descbc_ivlen(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav)
{
	if (!sav) {
		return 8;
	}
	if ((sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_IV4B)) {
		return 4;
	}
	if (!(sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_DERIV)) {
		return 4;
	}
	return 8;
}

static int
esp_des_schedlen(
	__unused const struct esp_algorithm *algo)
{
	return sizeof(des_ecb_key_schedule);
}

static int
esp_des_schedule(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav)
{
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	if (des_ecb_key_sched((des_cblock *)_KEYBUF(sav->key_enc),
	    (des_ecb_key_schedule *)sav->sched)) {
		return EINVAL;
	} else {
		return 0;
	}
}

static int
esp_des_blockdecrypt(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav,
	u_int8_t *s,
	u_int8_t *d)
{
	/* assumption: d has a good alignment */
	bcopy(s, d, sizeof(DES_LONG) * 2);
	return des_ecb_encrypt((des_cblock *)d, (des_cblock *)d,
	           (des_ecb_key_schedule *)sav->sched, DES_DECRYPT);
}

static int
esp_des_blockencrypt(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav,
	u_int8_t *s,
	u_int8_t *d)
{
	/* assumption: d has a good alignment */
	bcopy(s, d, sizeof(DES_LONG) * 2);
	return des_ecb_encrypt((des_cblock *)d, (des_cblock *)d,
	           (des_ecb_key_schedule *)sav->sched, DES_ENCRYPT);
}

static int
esp_cbc_mature(struct secasvar *sav)
{
	int keylen;
	const struct esp_algorithm *algo;

	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_cbc_mature: algorithm incompatible with esp-old\n"));
		return 1;
	}
	if (sav->flags & SADB_X_EXT_DERIV) {
		ipseclog((LOG_ERR,
		    "esp_cbc_mature: algorithm incompatible with derived\n"));
		return 1;
	}

	if (!sav->key_enc) {
		ipseclog((LOG_ERR, "esp_cbc_mature: no key is given.\n"));
		return 1;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_ERR,
		    "esp_cbc_mature: unsupported algorithm.\n"));
		return 1;
	}

	keylen = sav->key_enc->sadb_key_bits;
	if (keylen < algo->keymin || algo->keymax < keylen) {
		ipseclog((LOG_ERR,
		    "esp_cbc_mature %s: invalid key length %d.\n",
		    algo->name, sav->key_enc->sadb_key_bits));
		return 1;
	}
	switch (sav->alg_enc) {
	case SADB_EALG_3DESCBC:
		/* weak key check */
		if (des_is_weak_key((des_cblock *)_KEYBUF(sav->key_enc)) ||
		    des_is_weak_key((des_cblock *)(_KEYBUF(sav->key_enc) + 8)) ||
		    des_is_weak_key((des_cblock *)(_KEYBUF(sav->key_enc) + 16))) {
			ipseclog((LOG_ERR,
			    "esp_cbc_mature %s: weak key was passed.\n",
			    algo->name));
			return 1;
		}
		break;
	case SADB_X_EALG_RIJNDAELCBC:
		/* allows specific key sizes only */
		if (!(keylen == 128 || keylen == 192 || keylen == 256)) {
			ipseclog((LOG_ERR,
			    "esp_cbc_mature %s: invalid key length %d.\n",
			    algo->name, keylen));
			return 1;
		}
		break;
	}

	return 0;
}

static int
esp_gcm_mature(struct secasvar *sav)
{
	int keylen;
	const struct esp_algorithm *algo;

	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_gcm_mature: algorithm incompatible with esp-old\n"));
		return 1;
	}
	if (sav->flags & SADB_X_EXT_DERIV) {
		ipseclog((LOG_ERR,
		    "esp_gcm_mature: algorithm incompatible with derived\n"));
		return 1;
	}
	if (sav->flags & SADB_X_EXT_IIV) {
		ipseclog((LOG_ERR,
		    "esp_gcm_mature: implicit IV not currently implemented\n"));
		return 1;
	}

	if (!sav->key_enc) {
		ipseclog((LOG_ERR, "esp_gcm_mature: no key is given.\n"));
		return 1;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_ERR,
		    "esp_gcm_mature: unsupported algorithm.\n"));
		return 1;
	}

	keylen = sav->key_enc->sadb_key_bits;
	if (keylen < algo->keymin || algo->keymax < keylen) {
		ipseclog((LOG_ERR,
		    "esp_gcm_mature %s: invalid key length %d.\n",
		    algo->name, sav->key_enc->sadb_key_bits));
		return 1;
	}
	switch (sav->alg_enc) {
	case SADB_X_EALG_AES_GCM:
		/* allows specific key sizes only */
		if (!(keylen == ESP_AESGCM_KEYLEN128 || keylen == ESP_AESGCM_KEYLEN192 || keylen == ESP_AESGCM_KEYLEN256)) {
			ipseclog((LOG_ERR,
			    "esp_gcm_mature %s: invalid key length %d.\n",
			    algo->name, keylen));
			return 1;
		}
		break;
	default:
		ipseclog((LOG_ERR,
		    "esp_gcm_mature %s: invalid algo %d.\n", algo->name, sav->alg_enc));
		return 1;
	}

	return 0;
}

static int
esp_3des_schedlen(
	__unused const struct esp_algorithm *algo)
{
	return sizeof(des3_ecb_key_schedule);
}

static int
esp_3des_schedule(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav)
{
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	if (des3_ecb_key_sched((des_cblock *)_KEYBUF(sav->key_enc),
	    (des3_ecb_key_schedule *)sav->sched)) {
		return EINVAL;
	} else {
		return 0;
	}
}

static int
esp_3des_blockdecrypt(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav,
	u_int8_t *s,
	u_int8_t *d)
{
	/* assumption: d has a good alignment */
	bcopy(s, d, sizeof(DES_LONG) * 2);
	return des3_ecb_encrypt((des_cblock *)d, (des_cblock *)d,
	           (des3_ecb_key_schedule *)sav->sched, DES_DECRYPT);
}

static int
esp_3des_blockencrypt(
	__unused const struct esp_algorithm *algo,
	struct secasvar *sav,
	u_int8_t *s,
	u_int8_t *d)
{
	/* assumption: d has a good alignment */
	bcopy(s, d, sizeof(DES_LONG) * 2);
	return des3_ecb_encrypt((des_cblock *)d, (des_cblock *)d,
	           (des3_ecb_key_schedule *)sav->sched, DES_ENCRYPT);
}

static int
esp_common_ivlen(
	const struct esp_algorithm *algo,
	__unused struct secasvar *sav)
{
	if (!algo) {
		panic("esp_common_ivlen: unknown algorithm");
	}
	return algo->ivlenval;
}

static int
esp_cbc_decrypt(struct mbuf *m, size_t off, struct secasvar *sav,
    const struct esp_algorithm *algo, int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff, doff; /* offset from the head of chain, to head of this mbuf */
	int sn, dn;     /* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t iv[MAXIVLEN] __attribute__((aligned(4))), *ivp;
	u_int8_t *sbuf = NULL, *sp, *sp_unaligned;
	u_int8_t *p, *q;
	struct mbuf *scut;
	int scutoff;
	int i, result = 0;
	int blocklen;
	int derived;

	if (ivlen != sav->ivlen || ivlen > sizeof(iv)) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	/* assumes blocklen == padbound */
	blocklen = algo->padbound;

#if DIAGNOSTIC
	if (blocklen > sizeof(iv)) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "unsupported blocklen %d\n", algo->name, blocklen));
		m_freem(m);
		return EINVAL;
	}
#endif

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
		derived = 0;
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV) {
			/*
			 * draft-ietf-ipsec-ciph-des-derived-00.txt
			 * uses sequence number field as IV field.
			 */
			ivoff = off + sizeof(struct esp);
			bodyoff = off + sizeof(struct esp) + sizeof(u_int32_t);
			ivlen = sizeof(u_int32_t);
			derived = 1;
		} else {
			ivoff = off + sizeof(struct newesp);
			bodyoff = off + sizeof(struct newesp) + ivlen;
			derived = 0;
		}
	}

	/* grab iv */
	m_copydata(m, ivoff, ivlen, (caddr_t) iv);

	/* extend iv */
	if (ivlen == blocklen) {
		;
	} else if (ivlen == 4 && blocklen == 8) {
		bcopy(&iv[0], &iv[4], 4);
		iv[4] ^= 0xff;
		iv[5] ^= 0xff;
		iv[6] ^= 0xff;
		iv[7] ^= 0xff;
	} else {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported ivlen/blocklen: %d %d\n",
		    algo->name, ivlen, blocklen));
		m_freem(m);
		return EINVAL;
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: bad len %d/%u\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % blocklen) {
		ipseclog((LOG_ERR, "esp_cbc_decrypt %s: "
		    "payload length must be multiple of %d\n",
		    algo->name, blocklen));
		m_freem(m);
		return EINVAL;
	}

	s = m;
	d = d0 = dp = NULL;
	soff = doff = sn = dn = 0;
	ivp = sp = NULL;

	/* skip bodyoff */
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
	while (s && s->m_len == 0) {
		s = s->m_next;
	}

	// Allocate blocksized buffer for unaligned or non-contiguous access
	sbuf = (u_int8_t *)_MALLOC(blocklen, M_SECA, M_DONTWAIT);
	if (sbuf == NULL) {
		return ENOBUFS;
	}
	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + blocklen <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, blocklen, (caddr_t) sbuf);
			sp = sbuf;
		}

		/* destination */
		if (!d || dn + blocklen > d->m_len) {
			if (d) {
				dp = d;
			}
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					m_free(d);
					d = NULL;
				}
			}
			if (!d) {
				m_freem(m);
				if (d0) {
					m_freem(d0);
				}
				result = ENOBUFS;
				goto end;
			}
			if (!d0) {
				d0 = d;
			}
			if (dp) {
				dp->m_next = d;
			}

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = 0;
			d->m_len = (M_TRAILINGSPACE(d) / blocklen) * blocklen;
			if (d->m_len > i) {
				d->m_len = i;
			}
			dn = 0;
		}

		/* decrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is unaligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			sp = sbuf;
			memcpy(sp, sp_unaligned, blocklen);
		}
		// no need to check output pointer alignment
		(*algo->blockdecrypt)(algo, sav, sp, mtod(d, u_int8_t *) + dn);

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* xor */
		p = ivp ? ivp : iv;
		q = mtod(d, u_int8_t *) + dn;
		for (i = 0; i < blocklen; i++) {
			q[i] ^= p[i];
		}

		/* next iv */
		if (sp == sbuf) {
			bcopy(sbuf, iv, blocklen);
			ivp = NULL;
		} else {
			ivp = sp;
		}

		sn += blocklen;
		dn += blocklen;

		/* find the next source block */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	/* just in case */
	bzero(iv, sizeof(iv));
	bzero(sbuf, blocklen);
end:
	if (sbuf != NULL) {
		FREE(sbuf, M_SECA);
	}
	return result;
}

static int
esp_cbc_encrypt(
	struct mbuf *m,
	size_t off,
	__unused size_t plen,
	struct secasvar *sav,
	const struct esp_algorithm *algo,
	int ivlen)
{
	struct mbuf *s;
	struct mbuf *d, *d0, *dp;
	int soff, doff; /* offset from the head of chain, to head of this mbuf */
	int sn, dn;     /* offset from the head of the mbuf, to meat */
	size_t ivoff, bodyoff;
	u_int8_t iv[MAXIVLEN] __attribute__((aligned(4))), *ivp;
	u_int8_t *sbuf = NULL, *sp, *sp_unaligned;
	u_int8_t *p, *q;
	struct mbuf *scut;
	int scutoff;
	int i, result = 0;
	int blocklen;
	int derived;

	if (ivlen != sav->ivlen || ivlen > sizeof(iv)) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported ivlen %d\n", algo->name, ivlen));
		m_freem(m);
		return EINVAL;
	}

	/* assumes blocklen == padbound */
	blocklen = algo->padbound;

#if DIAGNOSTIC
	if (blocklen > sizeof(iv)) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported blocklen %d\n", algo->name, blocklen));
		m_freem(m);
		return EINVAL;
	}
#endif

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
		derived = 0;
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV) {
			/*
			 * draft-ietf-ipsec-ciph-des-derived-00.txt
			 * uses sequence number field as IV field.
			 */
			ivoff = off + sizeof(struct esp);
			bodyoff = off + sizeof(struct esp) + sizeof(u_int32_t);
			ivlen = sizeof(u_int32_t);
			derived = 1;
		} else {
			ivoff = off + sizeof(struct newesp);
			bodyoff = off + sizeof(struct newesp) + ivlen;
			derived = 0;
		}
	}

	/* put iv into the packet.  if we are in derived mode, use seqno. */
	if (derived) {
		m_copydata(m, ivoff, ivlen, (caddr_t) iv);
	} else {
		bcopy(sav->iv, iv, ivlen);
		/* maybe it is better to overwrite dest, not source */
		m_copyback(m, ivoff, ivlen, (caddr_t) iv);
	}

	/* extend iv */
	if (ivlen == blocklen) {
		;
	} else if (ivlen == 4 && blocklen == 8) {
		bcopy(&iv[0], &iv[4], 4);
		iv[4] ^= 0xff;
		iv[5] ^= 0xff;
		iv[6] ^= 0xff;
		iv[7] ^= 0xff;
	} else {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "unsupported ivlen/blocklen: %d %d\n",
		    algo->name, ivlen, blocklen));
		m_freem(m);
		return EINVAL;
	}

	if (m->m_pkthdr.len < bodyoff) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: bad len %d/%u\n",
		    algo->name, m->m_pkthdr.len, (u_int32_t)bodyoff));
		m_freem(m);
		return EINVAL;
	}
	if ((m->m_pkthdr.len - bodyoff) % blocklen) {
		ipseclog((LOG_ERR, "esp_cbc_encrypt %s: "
		    "payload length must be multiple of %u\n",
		    algo->name, (u_int32_t)algo->padbound));
		m_freem(m);
		return EINVAL;
	}

	s = m;
	d = d0 = dp = NULL;
	soff = doff = sn = dn = 0;
	ivp = sp = NULL;

	/* skip bodyoff */
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
	while (s && s->m_len == 0) {
		s = s->m_next;
	}

	// Allocate blocksized buffer for unaligned or non-contiguous access
	sbuf = (u_int8_t *)_MALLOC(blocklen, M_SECA, M_DONTWAIT);
	if (sbuf == NULL) {
		return ENOBUFS;
	}
	while (soff < m->m_pkthdr.len) {
		/* source */
		if (sn + blocklen <= s->m_len) {
			/* body is continuous */
			sp = mtod(s, u_int8_t *) + sn;
		} else {
			/* body is non-continuous */
			m_copydata(s, sn, blocklen, (caddr_t) sbuf);
			sp = sbuf;
		}

		/* destination */
		if (!d || dn + blocklen > d->m_len) {
			if (d) {
				dp = d;
			}
			MGET(d, M_DONTWAIT, MT_DATA);
			i = m->m_pkthdr.len - (soff + sn);
			if (d && i > MLEN) {
				MCLGET(d, M_DONTWAIT);
				if ((d->m_flags & M_EXT) == 0) {
					m_free(d);
					d = NULL;
				}
			}
			if (!d) {
				m_freem(m);
				if (d0) {
					m_freem(d0);
				}
				result = ENOBUFS;
				goto end;
			}
			if (!d0) {
				d0 = d;
			}
			if (dp) {
				dp->m_next = d;
			}

			// try to make mbuf data aligned
			if (!IPSEC_IS_P2ALIGNED(d->m_data)) {
				m_adj(d, IPSEC_GET_P2UNALIGNED_OFS(d->m_data));
			}

			d->m_len = 0;
			d->m_len = (M_TRAILINGSPACE(d) / blocklen) * blocklen;
			if (d->m_len > i) {
				d->m_len = i;
			}
			dn = 0;
		}

		/* xor */
		p = ivp ? ivp : iv;
		q = sp;
		for (i = 0; i < blocklen; i++) {
			q[i] ^= p[i];
		}

		/* encrypt */
		// check input pointer alignment and use a separate aligned buffer (if sp is not aligned on 4-byte boundary).
		if (IPSEC_IS_P2ALIGNED(sp)) {
			sp_unaligned = NULL;
		} else {
			sp_unaligned = sp;
			sp = sbuf;
			memcpy(sp, sp_unaligned, blocklen);
		}
		// no need to check output pointer alignment
		(*algo->blockencrypt)(algo, sav, sp, mtod(d, u_int8_t *) + dn);

		// update unaligned pointers
		if (!IPSEC_IS_P2ALIGNED(sp_unaligned)) {
			sp = sp_unaligned;
		}

		/* next iv */
		ivp = mtod(d, u_int8_t *) + dn;

		sn += blocklen;
		dn += blocklen;

		/* find the next source block */
		while (s && sn >= s->m_len) {
			sn -= s->m_len;
			soff += s->m_len;
			s = s->m_next;
		}
	}

	m_freem(scut->m_next);
	scut->m_len = scutoff;
	scut->m_next = d0;

	/* just in case */
	bzero(iv, sizeof(iv));
	bzero(sbuf, blocklen);

	key_sa_stir_iv(sav);
end:
	if (sbuf != NULL) {
		FREE(sbuf, M_SECA);
	}
	return result;
}

/*------------------------------------------------------------*/

/* does not free m0 on error */
int
esp_auth(
	struct mbuf *m0,
	size_t skip,    /* offset to ESP header */
	size_t length,  /* payload length */
	struct secasvar *sav,
	u_char *sum)
{
	struct mbuf *m;
	size_t off;
	struct ah_algorithm_state s;
	u_char sumbuf[AH_MAXSUMSIZE] __attribute__((aligned(4)));
	const struct ah_algorithm *algo;
	size_t siz;
	int error;

	/* sanity checks */
	if (m0->m_pkthdr.len < skip) {
		ipseclog((LOG_DEBUG, "esp_auth: mbuf length < skip\n"));
		return EINVAL;
	}
	if (m0->m_pkthdr.len < skip + length) {
		ipseclog((LOG_DEBUG,
		    "esp_auth: mbuf length < skip + length\n"));
		return EINVAL;
	}

	KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_START, skip, length, 0, 0, 0);
	/*
	 * length of esp part (excluding authentication data) must be 4n,
	 * since nexthdr must be at offset 4n+3.
	 */
	if (length % 4) {
		ipseclog((LOG_ERR, "esp_auth: length is not multiple of 4\n"));
		KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 1, 0, 0, 0, 0);
		return EINVAL;
	}
	if (!sav) {
		ipseclog((LOG_DEBUG, "esp_auth: NULL SA passed\n"));
		KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 2, 0, 0, 0, 0);
		return EINVAL;
	}
	algo = ah_algorithm_lookup(sav->alg_auth);
	if (!algo) {
		ipseclog((LOG_ERR,
		    "esp_auth: bad ESP auth algorithm passed: %d\n",
		    sav->alg_auth));
		KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 3, 0, 0, 0, 0);
		return EINVAL;
	}

	m = m0;
	off = 0;

	siz = (((*algo->sumsiz)(sav) + 3) & ~(4 - 1));
	if (sizeof(sumbuf) < siz) {
		ipseclog((LOG_DEBUG,
		    "esp_auth: AH_MAXSUMSIZE is too small: siz=%u\n",
		    (u_int32_t)siz));
		KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 4, 0, 0, 0, 0);
		return EINVAL;
	}

	/* skip the header */
	while (skip) {
		if (!m) {
			panic("mbuf chain?");
		}
		if (m->m_len <= skip) {
			skip -= m->m_len;
			m = m->m_next;
			off = 0;
		} else {
			off = skip;
			skip = 0;
		}
	}

	error = (*algo->init)(&s, sav);
	if (error) {
		KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 5, 0, 0, 0, 0);
		return error;
	}
	while (0 < length) {
		if (!m) {
			panic("mbuf chain?");
		}

		if (m->m_len - off < length) {
			(*algo->update)(&s, (caddr_t)(mtod(m, u_char *) + off),
			    m->m_len - off);
			length -= m->m_len - off;
			m = m->m_next;
			off = 0;
		} else {
			(*algo->update)(&s, (caddr_t)(mtod(m, u_char *) + off), length);
			break;
		}
	}
	(*algo->result)(&s, (caddr_t) sumbuf, sizeof(sumbuf));
	bcopy(sumbuf, sum, siz);        /*XXX*/
	KERNEL_DEBUG(DBG_FNC_ESPAUTH | DBG_FUNC_END, 6, 0, 0, 0, 0);
	return 0;
}

void
esp_init(void)
{
	static int esp_initialized = 0;

	if (esp_initialized) {
		return;
	}

	esp_initialized = 1;

	esp_mpkl_log_object = MPKL_CREATE_LOGOBJECT("com.apple.xnu.esp");
	if (esp_mpkl_log_object == NULL) {
		panic("MPKL_CREATE_LOGOBJECT for ESP failed");
	}

	return;
}
