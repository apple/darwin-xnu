/*	$KAME: esp_core.c,v 1.11 2000/02/22 14:04:15 itojun Exp $	*/

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
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

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
#include <netinet6/ah.h>
#include <netinet6/esp.h>
#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <crypto/des/des.h>
#include <crypto/blowfish/blowfish.h>
#include <crypto/cast128/cast128.h>
#include <crypto/rc5/rc5.h>

#include <net/net_osdep.h>

static int esp_null_mature __P((struct secasvar *));
static int esp_null_ivlen __P((struct secasvar *));
static int esp_null_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_null_encrypt __P((struct mbuf *, size_t, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_descbc_mature __P((struct secasvar *));
static int esp_descbc_ivlen __P((struct secasvar *));
static int esp_descbc_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_descbc_encrypt __P((struct mbuf *, size_t, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_cbc_mature __P((struct secasvar *));
static int esp_blowfish_cbc_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_blowfish_cbc_encrypt __P((struct mbuf *, size_t,
	size_t, struct secasvar *, struct esp_algorithm *, int));
static int esp_blowfish_cbc_ivlen __P((struct secasvar *));
static int esp_cast128cbc_ivlen __P((struct secasvar *));
static int esp_cast128cbc_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_cast128cbc_encrypt __P((struct mbuf *, size_t, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_3descbc_ivlen __P((struct secasvar *));
static int esp_3descbc_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_3descbc_encrypt __P((struct mbuf *, size_t, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_rc5cbc_ivlen __P((struct secasvar *));
static int esp_rc5cbc_decrypt __P((struct mbuf *, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static int esp_rc5cbc_encrypt __P((struct mbuf *, size_t, size_t,
	struct secasvar *, struct esp_algorithm *, int));
static void esp_increment_iv __P((struct secasvar *));
static caddr_t mbuf_find_offset __P((struct mbuf *, size_t, size_t));

/* NOTE: The order depends on SADB_EALG_x in netkey/keyv2.h */
struct esp_algorithm esp_algorithms[] = {
	{ 0, 0, 0, 0, 0, 0, 0, },
	{ 8, esp_descbc_mature, 64, 64,
		esp_descbc_ivlen, esp_descbc_decrypt, esp_descbc_encrypt, },
	{ 8, esp_cbc_mature, 192, 192,
		esp_3descbc_ivlen, esp_3descbc_decrypt, esp_3descbc_encrypt, },
	{ 1, esp_null_mature, 0, 2048,
		esp_null_ivlen, esp_null_decrypt, esp_null_encrypt, },
	{ 8, esp_cbc_mature, 40, 448,
		esp_blowfish_cbc_ivlen, esp_blowfish_cbc_decrypt,
		esp_blowfish_cbc_encrypt, },
	{ 8, esp_cbc_mature, 40, 128,
		esp_cast128cbc_ivlen, esp_cast128cbc_decrypt,
		esp_cast128cbc_encrypt, },
	{ 8, esp_cbc_mature, 40, 2040,
		esp_rc5cbc_ivlen, esp_rc5cbc_decrypt, esp_rc5cbc_encrypt, },
};

/*
 * mbuf assumption: foo_encrypt() assumes that IV part is placed in a single
 * mbuf, not across multiple mbufs.
 */

static int
esp_null_mature(sav)
	struct secasvar *sav;
{
	/* anything is okay */
	return 0;
}

static int
esp_null_ivlen(sav)
	struct secasvar *sav;
{
	return 0;
}

static int
esp_null_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;		/* offset to ESP header */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	return 0; /* do nothing */
}

static int
esp_null_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;	/* offset to ESP header */
	size_t plen;	/* payload length (to be encrypted) */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	return 0; /* do nothing */
}

static int
esp_descbc_mature(sav)
	struct secasvar *sav;
{
	struct esp_algorithm *algo;

	if (!(sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_IV4B)) {
		ipseclog((LOG_ERR, "esp_cbc_mature: "
		    "algorithm incompatible with 4 octets IV length\n"));
		return 1;
	}

	if (!sav->key_enc) {
		ipseclog((LOG_ERR, "esp_descbc_mature: no key is given.\n"));
		return 1;
	}
	algo = &esp_algorithms[sav->alg_enc];
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR,
		    "esp_descbc_mature: invalid key length %d.\n",
		    _KEYBITS(sav->key_enc)));
		return 1;
	}

	/* weak key check */
	if (des_is_weak_key((C_Block *)_KEYBUF(sav->key_enc))) {
		ipseclog((LOG_ERR,
		    "esp_descbc_mature: weak key was passed.\n"));
		return 1;
	}

	return 0;
}

static int
esp_descbc_ivlen(sav)
	struct secasvar *sav;
{
	if (sav && (sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_IV4B))
		return 4;

	if (sav && !(sav->flags & SADB_X_EXT_OLD) && (sav->flags & SADB_X_EXT_DERIV))
		return 4;
	else
		return 8;
}

static int
esp_descbc_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;		/* offset to ESP header */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff = 0;
	size_t bodyoff = 0;
	u_int8_t *iv;
	size_t plen;
	u_int8_t tiv[8];
	int derived;

	derived = 0;
	/* sanity check */
	if (ivlen != sav->ivlen) {
		ipseclog((LOG_ERR, "esp_descbc_decrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR, "esp_descbc_decrypt: bad keylen %d\n",
		    _KEYBITS(sav->key_enc)));
		return EINVAL;
	}

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
			 * This draft has been deleted, but you can get from
			 * ftp://ftp.kame.net/pub/internet-drafts/.
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
	if (ivlen == 4) {
		iv = &tiv[0];
		m_copydata(m, ivoff, 4, &tiv[0]);
		m_copydata(m, ivoff, 4, &tiv[4]);
		tiv[4] ^= 0xff;
		tiv[5] ^= 0xff;
		tiv[6] ^= 0xff;
		tiv[7] ^= 0xff;
	} else if (ivlen == 8) {
		iv = &tiv[0];
		m_copydata(m, ivoff, 8, &tiv[0]);
	} else {
		ipseclog((LOG_ERR, "esp_descbc_decrypt: unsupported ivlen %d\n",
		    ivlen));
		return EINVAL;
	}

	plen = m->m_pkthdr.len;
	if (plen < bodyoff)
		panic("esp_descbc_decrypt: too short packet: len=%lu",
		    (u_long)plen);
	plen -= bodyoff;

	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_descbc_decrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}

    {
	int deserr;
	des_key_schedule ks;

	deserr = des_key_sched((C_Block *)_KEYBUF(sav->key_enc), ks);
	if (deserr != 0) {
		ipseclog((LOG_ERR,
		    "esp_descbc_decrypt: key error %d\n", deserr));
		return EINVAL;
	}

	des_cbc_encrypt(m, bodyoff, plen, ks, (C_Block *)iv, DES_DECRYPT);

	/* for safety */
	bzero(&ks, sizeof(des_key_schedule));
    }

	/* for safety */
	bzero(&tiv[0], sizeof(tiv));

	return 0;
}

static int
esp_descbc_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;	/* offset to ESP header */
	size_t plen;	/* payload length (to be decrypted) */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff = 0;
	size_t bodyoff = 0;
	u_int8_t *iv;
	u_int8_t tiv[8];
	int derived;

	derived = 0;

	/* sanity check */
	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_descbc_encrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR, "esp_descbc_encrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR, "esp_descbc_encrypt: bad keylen %d\n",
		    _KEYBITS(sav->key_enc)));
		return EINVAL;
	}

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		/*
		 * draft-ietf-ipsec-ciph-des-derived-00.txt
		 * uses sequence number field as IV field.
		 * This draft has been deleted, see above.
		 */
		ivoff = off + sizeof(struct esp);
		bodyoff = off + sizeof(struct esp) + ivlen;
		derived = 0;
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV) {
			/*
			 * draft-ietf-ipsec-ciph-des-derived-00.txt
			 * uses sequence number field as IV field.
			 * This draft has been deleted, see above.
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

	if (m->m_pkthdr.len < bodyoff)
		panic("assumption failed: mbuf too short");
	iv = mbuf_find_offset(m, ivoff, ivlen);
	if (!iv)
		panic("assumption failed: bad mbuf chain");
	if (ivlen == 4) {
		if (!derived) {
			bcopy(sav->iv, &tiv[0], 4);
			bcopy(sav->iv, &tiv[4], 4);
			tiv[4] ^= 0xff;
			tiv[5] ^= 0xff;
			tiv[6] ^= 0xff;
			tiv[7] ^= 0xff;
			bcopy(&tiv[0], iv, 4);
			iv = &tiv[0];
		} else {
			bcopy(iv, &tiv[0], 4);
			bcopy(iv, &tiv[4], 4);
			tiv[4] ^= 0xff;
			tiv[5] ^= 0xff;
			tiv[6] ^= 0xff;
			tiv[7] ^= 0xff;
			iv = &tiv[0];
		}
	} else if (ivlen == 8)
		bcopy((caddr_t)sav->iv, (caddr_t)iv, ivlen);
	else {
		ipseclog((LOG_ERR,
		    "esp_descbc_encrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

    {
	int deserr;
	des_key_schedule ks;

	deserr = des_key_sched((C_Block *)_KEYBUF(sav->key_enc), ks);
	if (deserr != 0) {
		ipseclog((LOG_ERR,
		    "esp_descbc_encrypt: key error %d\n", deserr));
		return EINVAL;
	}

	des_cbc_encrypt(m, bodyoff, plen, ks, (C_Block *)iv, DES_ENCRYPT);

	/* for safety */
	bzero(&ks, sizeof(des_key_schedule));
    }

	esp_increment_iv(sav);

	/* for safety */
	bzero(&tiv[0], sizeof(tiv));

	return 0;
}

static int
esp_cbc_mature(sav)
	struct secasvar *sav;
{
	int keylen;
	struct esp_algorithm *algo;

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
		ipseclog((LOG_ERR,
		    "esp_cbc_mature: no key is given.\n"));
		return 1;
	}
	algo = &esp_algorithms[sav->alg_enc];
	keylen = sav->key_enc->sadb_key_bits;
	if (keylen < algo->keymin || algo->keymax < keylen) {
		ipseclog((LOG_ERR, "esp_cbc_mature: invalid key length %d.\n",
		    sav->key_enc->sadb_key_bits));
		return 1;
	}
	switch (sav->alg_enc) {
	case SADB_EALG_3DESCBC:
		/* weak key check */
		if (des_is_weak_key((C_Block *)_KEYBUF(sav->key_enc))
		 || des_is_weak_key((C_Block *)(_KEYBUF(sav->key_enc) + 8))
		 || des_is_weak_key((C_Block *)(_KEYBUF(sav->key_enc) + 16))) {
			ipseclog((LOG_ERR,
			    "esp_cbc_mature: weak key was passed.\n"));
			return 1;
		}
		break;
	case SADB_EALG_BLOWFISHCBC:
	case SADB_EALG_CAST128CBC:
	case SADB_EALG_RC5CBC:
		break;
	}

	return 0;
}

static int
esp_blowfish_cbc_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;		/* offset to ESP header */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;
	u_int8_t tiv[8];
	size_t plen;
	static BF_KEY key;	/* made static to avoid kernel stack overflow */
	int s;

	/* sanity check */
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_decrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_decrypt: unsupported key length %d: "
		    "need %d to %d bits\n", _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_decrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_decrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;
	iv = &tiv[0];
	m_copydata(m, ivoff, 8, &tiv[0]);

	plen = m->m_pkthdr.len;
	if (plen < bodyoff)
		panic("esp_blowfish_cbc_decrypt: too short packet: len=%lu",
		    (u_long)plen);
	plen -= bodyoff;

	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_blowfish_cbc_decrypt: "
			"payload length must be multiple of 8\n"));
		return EINVAL;
	}

#if __NetBSD__
	s = splsoftnet();	/* XXX correct? */
#else
	s = splnet();	/* XXX correct? */
#endif

	BF_set_key(&key, _KEYBITS(sav->key_enc) / 8, _KEYBUF(sav->key_enc));
	BF_cbc_encrypt_m(m, bodyoff, plen, &key, iv, BF_DECRYPT);

	/* for safety */
	bzero(&key, sizeof(BF_KEY));

	splx(s);

	/* for safety */
	bzero(&tiv[0], sizeof(tiv));

	return 0;
}

static int
esp_blowfish_cbc_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;	/* offset to ESP header */
	size_t plen;	/* payload length (to be decrypted) */
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;
	static BF_KEY key;	/* made static to avoid kernel stack overflow */
	int s;

	/* sanity check */
	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_blowfish_cbc_encrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_encrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_encrypt: unsupported key length %d: "
		    "need %d to %d bits\n", _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_encrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_blowfish_cbc_encrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	if (m->m_pkthdr.len < bodyoff)
		panic("assumption failed: mbuf too short");
	iv = mbuf_find_offset(m, ivoff, ivlen);
	if (!iv)
		panic("assumption failed: bad mbuf chain");

	bcopy((caddr_t)sav->iv, (caddr_t)iv, ivlen);

#if __NetBSD__
	s = splsoftnet();	/* XXX correct? */
#else
	s = splnet();	/* XXX correct? */
#endif

	BF_set_key(&key, _KEYBITS(sav->key_enc) / 8, _KEYBUF(sav->key_enc));
	BF_cbc_encrypt_m(m, bodyoff, plen, &key, iv, BF_ENCRYPT);

	/* for safety */
	bzero(&key, sizeof(BF_KEY));

	splx(s);

	esp_increment_iv(sav);

	return 0;
}

static int
esp_blowfish_cbc_ivlen(sav)
	struct secasvar *sav;
{
	return 8;
}

static int
esp_cast128cbc_ivlen(sav)
	struct secasvar *sav;
{
	return 8;
}

static int
esp_cast128cbc_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t iv[8];
	size_t plen;

	/* sanity check */
	if (ivlen != sav->ivlen) {
		ipseclog((LOG_ERR, "esp_cast128cbc_decrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || _KEYBITS(sav->key_enc) > algo->keymax) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_decrypt: unsupported key length %d: "
		    "need %d to %d bits\n", _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_decrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_decrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	/* copy mbuf's IV into iv */
	m_copydata(m, ivoff, 8, iv);

	plen = m->m_pkthdr.len;
	if (plen < bodyoff) {
		panic("esp_cast128cbc_decrypt: too short packet: len=%lu\n",
		    (u_long)plen);
	}
	plen -= bodyoff;

	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_cast128cbc_decrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}

	/* decrypt */
    {
	u_int8_t key[16];
	u_int32_t subkey[32];

	bzero(key, sizeof(key));
	bcopy(_KEYBUF(sav->key_enc), key, _KEYLEN(sav->key_enc));

	set_cast128_subkey(subkey, key);
	cast128_cbc_process(m, bodyoff, plen, subkey, iv,
				_KEYBITS(sav->key_enc) / 8, CAST128_DECRYPT);

	/* for safety */
	bzero(subkey, sizeof(subkey));
	bzero(key, sizeof(key));
    }

	return 0;
}

static int
esp_cast128cbc_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	size_t plen;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;

	/* sanity check */
	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_cast128cbc_encrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR, "esp_cast128cbc_encrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || _KEYBITS(sav->key_enc) > algo->keymax) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_encrypt: unsupported key length %d: "
		    "needs %d to %d bits\n", _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_encrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_cast128cbc_encrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	if (m->m_pkthdr.len < bodyoff)
		panic("assumption failed: mbuf too short");
	iv = mbuf_find_offset(m, ivoff, ivlen);
	if (!iv)
		panic("assumption failed: bad mbuf chain");

	bcopy(sav->iv, iv, ivlen);

	/* encrypt */
    {
	u_int8_t key[16];
	u_int32_t subkey[32];

	bzero(key, sizeof(key));
	bcopy(_KEYBUF(sav->key_enc), key, _KEYLEN(sav->key_enc));

	set_cast128_subkey(subkey, key);
	cast128_cbc_process(m, bodyoff, plen, subkey, iv,
				_KEYBITS(sav->key_enc) / 8, CAST128_ENCRYPT);

	/* for safety */
	bzero(subkey, sizeof(subkey));
	bzero(key, sizeof(key));
    }

	esp_increment_iv(sav);

	return 0;
}

static int
esp_3descbc_ivlen(sav)
	struct secasvar *sav;
{
	return 8;
}

static int
esp_3descbc_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;
	size_t plen;
	u_int8_t tiv[8];

	/* sanity check */
	if (ivlen != sav->ivlen) {
		ipseclog((LOG_ERR, "esp_3descbc_decrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR, "esp_3descbc_decrypt: bad keylen %d\n",
		    _KEYBITS(sav->key_enc)));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_3descbc_decrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_3descbc_decrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;
	iv = &tiv[0];
	m_copydata(m, ivoff, 8, &tiv[0]);

	plen = m->m_pkthdr.len;
	if (plen < bodyoff)
		panic("esp_3descbc_decrypt: too short packet: len=%lu",
		   (u_long)plen);

	plen -= bodyoff;

	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_3descbc_decrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}

	/* decrypt packet */
    {
	int deserr[3];
	des_key_schedule ks[3];

	deserr[0] = des_key_sched((C_Block *)_KEYBUF(sav->key_enc),ks[0]);
	deserr[1] = des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 8), ks[1]);
	deserr[2] = des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 16), ks[2]);
	if ((deserr[0] != 0) || (deserr[1] != 0) || (deserr[2] != 0)) {
		ipseclog((LOG_ERR, "esp_3descbc_decrypt: key error %d/%d/%d\n",
		    deserr[0], deserr[1], deserr[2]));
		return EINVAL;
	}

	des_3cbc_process(m, bodyoff, plen, ks, (C_Block *)iv, DES_DECRYPT);

	/* for safety */
	bzero(ks[0], sizeof(des_key_schedule)*3);
    }

	/* for safety */
	bzero(&tiv[0], sizeof(tiv));

	return 0;
}

static int
esp_3descbc_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	size_t plen;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;

	/* sanity check */
	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_3descbc_encrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR, "esp_3descbc_encrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || algo->keymax < _KEYBITS(sav->key_enc)) {
		ipseclog((LOG_ERR, "esp_3descbc_encrypt: bad keylen %d\n",
		    _KEYBITS(sav->key_enc)));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_3descbc_encrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR,
		    "esp_3descbc_encrypt: unsupported ivlen %d\n", ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	if (m->m_pkthdr.len < bodyoff)
		panic("assumption failed: mbuf too short");
	iv = mbuf_find_offset(m, ivoff, ivlen);
	if (!iv)
		panic("assumption failed: bad mbuf chain");

	bcopy((caddr_t)sav->iv, (caddr_t)iv, ivlen);

	/* encrypt packet */
    {
	int deserr[3];
	des_key_schedule ks[3];

	deserr[0] = des_key_sched((C_Block *)_KEYBUF(sav->key_enc),     ks[0]);
	deserr[1] = des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 8), ks[1]);
	deserr[2] = des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 16), ks[2]);
	if ((deserr[0] != 0) || (deserr[1] != 0) || (deserr[2] != 0)) {
		ipseclog((LOG_ERR, "esp_3descbc_encrypt: key error %d/%d/%d\n",
		    deserr[0], deserr[1], deserr[2]));
		return EINVAL;
	}

	des_3cbc_process(m, bodyoff, plen, ks, (C_Block *)iv, DES_ENCRYPT);

	/* for safety */
	bzero(ks[0], sizeof(des_key_schedule)*3);
    }

	esp_increment_iv(sav);

	return 0;
}

static int
esp_rc5cbc_ivlen(sav)
	struct secasvar *sav;
{
	return 8;
}

static int
esp_rc5cbc_decrypt(m, off, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t iv[8];
	size_t plen;

	/* sanity check */
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR, "esp_rc5cbc_decrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if ((_KEYBITS(sav->key_enc) < 40) || (_KEYBITS(sav->key_enc) > 2040)) {
		ipseclog((LOG_ERR,
		    "esp_rc5cbc_decrypt: unsupported key length %d: "
		    "need 40 to 2040 bit\n", _KEYBITS(sav->key_enc)));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_rc5cbc_decrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR, "esp_rc5cbc_decrypt: unsupported ivlen %d\n",
		    ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	/* copy mbuf's IV into iv */
	m_copydata(m, ivoff, 8, iv);

	plen = m->m_pkthdr.len;
	if (plen < bodyoff) {
		panic("esp_rc5cbc_decrypt: too short packet: len=%lu",
			(u_long)plen);
	}
	plen -= bodyoff;

	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_rc5cbc_decrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}

	/* decrypt */
    {
	RC5_WORD e_key[34];

	set_rc5_expandkey(e_key, _KEYBUF(sav->key_enc),
			_KEYBITS(sav->key_enc) / 8, 16);
	rc5_cbc_process(m, bodyoff, plen, e_key, iv, RC5_DECRYPT);

	/* for safety */
	bzero(e_key, sizeof(e_key));
    }

	return 0;
}

static int
esp_rc5cbc_encrypt(m, off, plen, sav, algo, ivlen)
	struct mbuf *m;
	size_t off;
	size_t plen;
	struct secasvar *sav;
	struct esp_algorithm *algo;
	int ivlen;
{
	size_t ivoff;
	size_t bodyoff;
	u_int8_t *iv;

	/* sanity check */
	if (plen % 8) {
		ipseclog((LOG_ERR, "esp_rc5cbc_encrypt: "
		    "payload length must be multiple of 8\n"));
		return EINVAL;
	}
	if (sav->ivlen != ivlen) {
		ipseclog((LOG_ERR, "esp_rc5cbc_encrypt: bad ivlen %d/%d\n",
		    ivlen, sav->ivlen));
		return EINVAL;
	}
	if (_KEYBITS(sav->key_enc) < algo->keymin
	 || _KEYBITS(sav->key_enc) > algo->keymax) {
		ipseclog((LOG_ERR,
		    "esp_rc5cbc_encrypt: unsupported key length %d: "
		    "need %d to %d bits\n", _KEYBITS(sav->key_enc),
		    algo->keymin, algo->keymax));
		return EINVAL;
	}
	if (sav->flags & SADB_X_EXT_OLD) {
		ipseclog((LOG_ERR,
		    "esp_rc5cbc_encrypt: unsupported ESP version\n"));
		return EINVAL;
	}
	if (ivlen != 8) {
		ipseclog((LOG_ERR, "esp_rc5cbc_encrypt: unsupported ivlen %d\n",
		    ivlen));
		return EINVAL;
	}

	ivoff = off + sizeof(struct newesp);
	bodyoff = off + sizeof(struct newesp) + ivlen;

	if (m->m_pkthdr.len < bodyoff)
		panic("assumption failed: mbuf too short");
	iv = mbuf_find_offset(m, ivoff, ivlen);
	if (!iv)
		panic("assumption failed: bad mbuf chain");

	bcopy(sav->iv, iv, ivlen);

	/* encrypt */
    {
	RC5_WORD e_key[34];

	set_rc5_expandkey(e_key, _KEYBUF(sav->key_enc),
			_KEYBITS(sav->key_enc) / 8, 16);
	rc5_cbc_process(m, bodyoff, plen, e_key, iv, RC5_ENCRYPT);

	/* for safety */
	bzero(e_key, sizeof(e_key));
    }

	esp_increment_iv(sav);

	return 0;
}

/*
 * increment iv.
 */
static void
esp_increment_iv(sav)
	struct secasvar *sav;
{
	u_int8_t *x;
	u_int8_t y;
	int i;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	y = time.tv_sec & 0xff;
#else
	y = time_second & 0xff;
#endif
	if (!y) y++;
	x = (u_int8_t *)sav->iv;
	for (i = 0; i < sav->ivlen; i++) {
		*x = (*x + y) & 0xff;
		x++;
	}
}

static caddr_t
mbuf_find_offset(m, off, len)
	struct mbuf *m;
	size_t off;
	size_t len;
{
	struct mbuf *n;
	size_t cnt;

	if (m->m_pkthdr.len < off || m->m_pkthdr.len < off + len)
		return (caddr_t)NULL;
	cnt = 0;
	for (n = m; n; n = n->m_next) {
		if (cnt + n->m_len <= off) {
			cnt += n->m_len;
			continue;
		}
		if (cnt <= off && off < cnt + n->m_len
		 && cnt <= off + len && off + len <= cnt + n->m_len) {
			return mtod(n, caddr_t) + off - cnt;
		} else
			return (caddr_t)NULL;
	}
	return (caddr_t)NULL;
}

/*------------------------------------------------------------*/

int
esp_auth(m0, skip, length, sav, sum)
	struct mbuf *m0;
	size_t skip;	/* offset to ESP header */
	size_t length;	/* payload length */
	struct secasvar *sav;
	u_char *sum;
{
	struct mbuf *m;
	size_t off;
	struct ah_algorithm_state s;
	u_char sumbuf[AH_MAXSUMSIZE];
	struct ah_algorithm *algo;
	size_t siz;

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
	/*
	 * length of esp part (excluding authentication data) must be 4n,
	 * since nexthdr must be at offset 4n+3.
	 */
	if (length % 4) {
		ipseclog((LOG_ERR, "esp_auth: length is not multiple of 4\n"));
		return EINVAL;
	}
	if (!sav) {
		ipseclog((LOG_DEBUG, "esp_auth: NULL SA passed\n"));
		return EINVAL;
	}
	if (!sav->alg_auth) {
		ipseclog((LOG_ERR,
		    "esp_auth: bad ESP auth algorithm passed: %d\n",
		    sav->alg_auth));
		return EINVAL;
	}

	m = m0;
	off = 0;

	algo = &ah_algorithms[sav->alg_auth];
	siz = (((*algo->sumsiz)(sav) + 3) & ~(4 - 1));
	if (sizeof(sumbuf) < siz) {
		ipseclog((LOG_DEBUG,
		    "esp_auth: AH_MAXSUMSIZE is too small: siz=%lu\n",
		    (u_long)siz));
		return EINVAL;
	}

	/* skip the header */
	while (skip) {
		if (!m)
			panic("mbuf chain?");
		if (m->m_len <= skip) {
			skip -= m->m_len;
			m = m->m_next;
			off = 0;
		} else {
			off = skip;
			skip = 0;
		}
	}

	(*algo->init)(&s, sav);
	while (0 < length) {
		if (!m)
			panic("mbuf chain?");

		if (m->m_len - off < length) {
			(*algo->update)(&s, mtod(m, u_char *) + off,
				m->m_len - off);
			length -= m->m_len - off;
			m = m->m_next;
			off = 0;
		} else {
			(*algo->update)(&s, mtod(m, u_char *) + off, length);
			break;
		}
	}
	(*algo->result)(&s, sumbuf);
	bcopy(sumbuf, sum, siz);	/*XXX*/
	
	return 0;
}
