/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/random.h>
#include <mach_assert.h>
#include <kern/assert.h>
#include <libkern/OSAtomic.h>
#include "gss_krb5_mech.h"

lck_grp_t *gss_krb5_mech_grp;

typedef struct crypt_walker_ctx {
	size_t length;
	const struct ccmode_cbc *ccmode;
	cccbc_ctx *crypt_ctx;
	cccbc_iv *iv;
} *crypt_walker_ctx_t;

typedef struct hmac_walker_ctx {
	const struct ccdigest_info *di;
	struct cchmac_ctx *hmac_ctx;
} *hmac_walker_ctx_t;

typedef size_t (*ccpad_func)(const struct ccmode_cbc *, cccbc_ctx *, cccbc_iv *,
    size_t nbytes, const void *, void *);

static int krb5_n_fold(const void *instr, size_t len, void *foldstr, size_t size);

size_t gss_mbuf_len(mbuf_t, size_t);
errno_t gss_prepend_mbuf(mbuf_t *, uint8_t *, size_t);
errno_t gss_append_mbuf(mbuf_t, uint8_t *, size_t);
errno_t gss_strip_mbuf(mbuf_t, ssize_t);
int mbuf_walk(mbuf_t, size_t, size_t, size_t, int (*)(void *, uint8_t *, uint32_t), void *);

void do_crypt_init(crypt_walker_ctx_t, int, crypto_ctx_t, cccbc_ctx *);
int do_crypt(void *, uint8_t *, uint32_t);
void do_hmac_init(hmac_walker_ctx_t, crypto_ctx_t, void *);
int do_hmac(void *, uint8_t *, uint32_t);

void krb5_make_usage(uint32_t, uint8_t, uint8_t[KRB5_USAGE_LEN]);
void krb5_key_derivation(crypto_ctx_t, const void *, size_t, void **, size_t);
void cc_key_schedule_create(crypto_ctx_t);
void gss_crypto_ctx_free(crypto_ctx_t);
int gss_crypto_ctx_init(struct crypto_ctx *, lucid_context_t);

errno_t krb5_crypt_mbuf(crypto_ctx_t, mbuf_t *, uint32_t, int, cccbc_ctx *);
int krb5_mic(crypto_ctx_t, gss_buffer_t, gss_buffer_t, gss_buffer_t, uint8_t *, int *, int, int);
int krb5_mic_mbuf(crypto_ctx_t, gss_buffer_t, mbuf_t, uint32_t, uint32_t, gss_buffer_t, uint8_t *, int *, int, int);

uint32_t gss_krb5_cfx_get_mic(uint32_t *, gss_ctx_id_t, gss_qop_t, gss_buffer_t, gss_buffer_t);
uint32_t gss_krb5_cfx_verify_mic(uint32_t *, gss_ctx_id_t, gss_buffer_t, gss_buffer_t, gss_qop_t *);
uint32_t gss_krb5_cfx_get_mic_mbuf(uint32_t *, gss_ctx_id_t, gss_qop_t, mbuf_t, size_t, size_t, gss_buffer_t);
uint32_t gss_krb5_cfx_verify_mic_mbuf(uint32_t *, gss_ctx_id_t, mbuf_t, size_t, size_t, gss_buffer_t, gss_qop_t *);
errno_t krb5_cfx_crypt_mbuf(crypto_ctx_t, mbuf_t *, size_t *, int, int);
uint32_t gss_krb5_cfx_wrap_mbuf(uint32_t *, gss_ctx_id_t, int, gss_qop_t, mbuf_t *, size_t, int *);
uint32_t gss_krb5_cfx_unwrap_mbuf(uint32_t *, gss_ctx_id_t, mbuf_t *, size_t, int *, gss_qop_t *);

int gss_krb5_mech_is_initialized(void);
void gss_krb5_mech_init(void);

/* Debugging routines */
void
printmbuf(const char *str, mbuf_t mb, uint32_t offset, uint32_t len)
{
	size_t i;
	int cout = 1;

	len = len ? len : ~0;
	printf("%s mbuf = %p offset = %d len = %d:\n", str ? str : "mbuf", mb, offset, len);
	for (; mb && len; mb = mbuf_next(mb)) {
		if (offset >= mbuf_len(mb)) {
			offset -= mbuf_len(mb);
			continue;
		}
		for (i = offset; len && i < mbuf_len(mb); i++) {
			const char *s = (cout % 8) ? " " : (cout % 16) ? "    " : "\n";
			printf("%02x%s", ((uint8_t *)mbuf_data(mb))[i], s);
			len--;
			cout++;
		}
		offset = 0;
	}
	if ((cout - 1) % 16) {
		printf("\n");
	}
	printf("Count chars %d\n", cout - 1);
}

void
printgbuf(const char *str, gss_buffer_t buf)
{
	size_t i;
	size_t len = buf->length > 128 ? 128 : buf->length;

	printf("%s:   len = %d value = %p\n", str ? str : "buffer", (int)buf->length, buf->value);
	for (i = 0; i < len; i++) {
		const char *s = ((i + 1) % 8) ? " " : ((i + 1) % 16) ? "    " : "\n";
		printf("%02x%s", ((uint8_t *)buf->value)[i], s);
	}
	if (i % 16) {
		printf("\n");
	}
}

/*
 * Initialize the data structures for the gss kerberos mech.
 */
#define GSS_KRB5_NOT_INITIALIZED        0
#define GSS_KRB5_INITIALIZING   1
#define GSS_KRB5_INITIALIZED    2
static volatile uint32_t gss_krb5_mech_initted = GSS_KRB5_NOT_INITIALIZED;

int
gss_krb5_mech_is_initialized(void)
{
	return gss_krb5_mech_initted == GSS_KRB5_NOT_INITIALIZED;
}

void
gss_krb5_mech_init(void)
{
	extern void IOSleep(int);

	/* Once initted always initted */
	if (gss_krb5_mech_initted == GSS_KRB5_INITIALIZED) {
		return;
	}

	/* make sure we init only once */
	if (!OSCompareAndSwap(GSS_KRB5_NOT_INITIALIZED, GSS_KRB5_INITIALIZING, &gss_krb5_mech_initted)) {
		/* wait until initialization is complete */
		while (!gss_krb5_mech_is_initialized()) {
			IOSleep(10);
		}
		return;
	}
	gss_krb5_mech_grp = lck_grp_alloc_init("gss_krb5_mech", LCK_GRP_ATTR_NULL);
	gss_krb5_mech_initted = GSS_KRB5_INITIALIZED;
}

uint32_t
gss_release_buffer(uint32_t *minor, gss_buffer_t buf)
{
	if (minor) {
		*minor = 0;
	}
	if (buf->value) {
		FREE(buf->value, M_TEMP);
	}
	buf->value = NULL;
	buf->length = 0;
	return GSS_S_COMPLETE;
}

/*
 * GSS mbuf routines
 */

size_t
gss_mbuf_len(mbuf_t mb, size_t offset)
{
	size_t len;

	for (len = 0; mb; mb = mbuf_next(mb)) {
		len += mbuf_len(mb);
	}
	return (offset > len) ? 0 : len - offset;
}

/*
 * Split an mbuf in a chain into two mbufs such that the original mbuf
 * points to the original mbuf and the new mbuf points to the rest of the
 * chain. The first mbuf length is the first len bytes and the second
 * mbuf contains the remaining bytes. if len is zero or equals
 * mbuf_len(mb) the don't create a new mbuf. We are already at an mbuf
 * boundary. Return the mbuf that starts at the offset.
 */
static errno_t
split_one_mbuf(mbuf_t mb, size_t offset, mbuf_t *nmb, int join)
{
	errno_t error;

	*nmb = mb;
	/* We don't have an mbuf or we're alread on an mbuf boundary */
	if (mb == NULL || offset == 0) {
		return 0;
	}

	/* If the mbuf length is offset then the next mbuf is the one we want */
	if (mbuf_len(mb) == offset) {
		*nmb = mbuf_next(mb);
		if (!join) {
			mbuf_setnext(mb, NULL);
		}
		return 0;
	}

	if (offset > mbuf_len(mb)) {
		return EINVAL;
	}

	error = mbuf_split(mb, offset, MBUF_WAITOK, nmb);
	if (error) {
		return error;
	}

	if (mbuf_flags(*nmb) & MBUF_PKTHDR) {
		/* We don't want to copy the pkthdr. mbuf_split does that. */
		error = mbuf_setflags_mask(*nmb, ~MBUF_PKTHDR, MBUF_PKTHDR);
	}

	if (join) {
		/* Join the chain again */
		mbuf_setnext(mb, *nmb);
	}

	return 0;
}

/*
 * Given an mbuf with an offset and length return the chain such that
 * offset and offset + *subchain_length are on mbuf boundaries.  If
 * *mbuf_length is less that the length of the chain after offset
 * return that length in *mbuf_length. The mbuf sub chain starting at
 * offset is returned in *subchain. If an error occurs return the
 * corresponding errno. Note if there are less than offset bytes then
 * subchain will be set to NULL and *subchain_length will be set to
 * zero. If *subchain_length is 0; then set it to the length of the
 * chain starting at offset. Join parameter is used to indicate whether
 * the mbuf chain will be joined again as on chain, just rearranged so
 * that offset and subchain_length are on mbuf boundaries.
 */

errno_t
gss_normalize_mbuf(mbuf_t chain, size_t offset, size_t *subchain_length, mbuf_t *subchain, mbuf_t *tail, int join)
{
	size_t length = *subchain_length ? *subchain_length : ~0;
	size_t len;
	mbuf_t mb, nmb;
	errno_t error;

	if (tail == NULL) {
		tail = &nmb;
	}
	*tail = NULL;
	*subchain = NULL;

	for (len = offset, mb = chain; mb && len > mbuf_len(mb); mb = mbuf_next(mb)) {
		len -= mbuf_len(mb);
	}

	/* if we don't have offset bytes just return */
	if (mb == NULL) {
		return 0;
	}

	error = split_one_mbuf(mb, len, subchain, join);
	if (error) {
		return error;
	}

	assert(subchain != NULL && *subchain != NULL);
	assert(offset == 0 ? mb == *subchain : 1);

	len = gss_mbuf_len(*subchain, 0);
	length =  (length > len) ? len : length;
	*subchain_length = length;

	for (len = length, mb = *subchain; mb && len > mbuf_len(mb); mb = mbuf_next(mb)) {
		len -= mbuf_len(mb);
	}

	error = split_one_mbuf(mb, len, tail, join);

	return error;
}

mbuf_t
gss_join_mbuf(mbuf_t head, mbuf_t body, mbuf_t tail)
{
	mbuf_t mb;

	for (mb = head; mb && mbuf_next(mb); mb = mbuf_next(mb)) {
		;
	}
	if (mb) {
		mbuf_setnext(mb, body);
	}
	for (mb = body; mb && mbuf_next(mb); mb = mbuf_next(mb)) {
		;
	}
	if (mb) {
		mbuf_setnext(mb, tail);
	}
	mb = head ? head : (body ? body : tail);
	return mb;
}

/*
 * Prepend size bytes to the mbuf chain.
 */
errno_t
gss_prepend_mbuf(mbuf_t *chain, uint8_t *bytes, size_t size)
{
	uint8_t *data = mbuf_data(*chain);
	size_t leading = mbuf_leadingspace(*chain);
	size_t trailing = mbuf_trailingspace(*chain);
	size_t mlen = mbuf_len(*chain);
	errno_t error;

	if (size > leading && size <= leading + trailing) {
		data = memmove(data + size - leading, data, mlen);
		mbuf_setdata(*chain, data, mlen);
	}

	error = mbuf_prepend(chain, size, MBUF_WAITOK);
	if (error) {
		return error;
	}
	data = mbuf_data(*chain);
	memcpy(data, bytes, size);

	return 0;
}

errno_t
gss_append_mbuf(mbuf_t chain, uint8_t *bytes, size_t size)
{
	size_t len = 0;
	mbuf_t mb;

	if (chain == NULL) {
		return EINVAL;
	}

	for (mb = chain; mb; mb = mbuf_next(mb)) {
		len += mbuf_len(mb);
	}

	return mbuf_copyback(chain, len, size, bytes, MBUF_WAITOK);
}

errno_t
gss_strip_mbuf(mbuf_t chain, ssize_t size)
{
	if (chain == NULL) {
		return EINVAL;
	}

	mbuf_adj(chain, size);

	return 0;
}


/*
 * Kerberos mech generic crypto support for mbufs
 */

/*
 * Walk the mbuf after the given offset calling the passed in crypto function
 * for len bytes. Note the length, len should be a multiple of the  blocksize and
 * there should be at least len bytes available after the offset in the mbuf chain.
 * padding should be done before calling this routine.
 */
int
mbuf_walk(mbuf_t mbp, size_t offset, size_t len, size_t blocksize, int (*crypto_fn)(void *, uint8_t *data, uint32_t length), void *ctx)
{
	mbuf_t mb;
	size_t mlen, residue;
	uint8_t *ptr;
	int error = 0;

	/* Move to the start of the chain */
	for (mb = mbp; mb && len > 0; mb = mbuf_next(mb)) {
		ptr = mbuf_data(mb);
		mlen = mbuf_len(mb);
		if (offset >= mlen) {
			/* Offset not yet reached */
			offset -= mlen;
			continue;
		}
		/* Found starting point in chain */
		ptr += offset;
		mlen -= offset;
		offset = 0;

		/*
		 * Handle the data in this mbuf. If the length to
		 * walk is less than the data in the mbuf, set
		 * the mbuf length left to be the length left
		 */
		mlen = mlen < len ? mlen : len;
		/* Figure out how much is a multple of blocksize */
		residue = mlen % blocksize;
		/* And addjust the mleft length to be the largest multiple of blocksized */
		mlen -= residue;
		/* run our hash/encrypt/decrpyt function */
		if (mlen > 0) {
			error = crypto_fn(ctx, ptr, mlen);
			if (error) {
				break;
			}
			ptr += mlen;
			len -= mlen;
		}
		/*
		 * If we have a residue then to get a full block for our crypto
		 * function, we need to copy the residue into our block size
		 * block and use the next mbuf to get the rest of the data for
		 * the block.  N.B. We generally assume that from the offset
		 * passed in, that the total length, len, is a multple of
		 * blocksize and that there are at least len bytes in the chain
		 * from the offset.  We also assume there is at least (blocksize
		 * - residue) size data in any next mbuf for residue > 0. If not
		 * we attemp to pullup bytes from down the chain.
		 */
		if (residue) {
			mbuf_t nmb = mbuf_next(mb);
			uint8_t *nptr = NULL, block[blocksize];

			assert(nmb);
			len -= residue;
			offset = blocksize - residue;
			if (len < offset) {
				offset = len;
				/*
				 * We don't have enough bytes so zero the block
				 * so that any trailing bytes will be zero.
				 */
				cc_clear(sizeof(block), block);
			}
			memcpy(block, ptr, residue);
			if (len && nmb) {
				mlen = mbuf_len(nmb);
				if (mlen < offset) {
					error = mbuf_pullup(&nmb, offset - mlen);
					if (error) {
						mbuf_setnext(mb, NULL);
						return error;
					}
				}
				nptr = mbuf_data(nmb);
				memcpy(block + residue, nptr, offset);
			}
			len -= offset;
			error = crypto_fn(ctx, block, sizeof(block));
			if (error) {
				break;
			}
			memcpy(ptr, block, residue);
			if (nptr) {
				memcpy(nptr, block + residue, offset);
			}
		}
	}

	return error;
}

void
do_crypt_init(crypt_walker_ctx_t wctx, int encrypt, crypto_ctx_t cctx, cccbc_ctx *ks)
{
	wctx->ccmode = encrypt ? cctx->enc_mode : cctx->dec_mode;

	wctx->crypt_ctx = ks;
	MALLOC(wctx->iv, cccbc_iv *, wctx->ccmode->block_size, M_TEMP, M_WAITOK | M_ZERO);
	cccbc_set_iv(wctx->ccmode, wctx->iv, NULL);
}

int
do_crypt(void *walker, uint8_t *data, uint32_t len)
{
	struct crypt_walker_ctx *wctx = (crypt_walker_ctx_t)walker;
	uint32_t nblocks;

	nblocks = len / wctx->ccmode->block_size;
	assert(len % wctx->ccmode->block_size == 0);
	cccbc_update(wctx->ccmode, wctx->crypt_ctx, wctx->iv, nblocks, data, data);
	wctx->length += len;

	return 0;
}

void
do_hmac_init(hmac_walker_ctx_t wctx, crypto_ctx_t cctx, void *key)
{
	size_t alloc_size = cchmac_di_size(cctx->di);

	wctx->di = cctx->di;
	MALLOC(wctx->hmac_ctx, struct cchmac_ctx *, alloc_size, M_TEMP, M_WAITOK | M_ZERO);
	cchmac_init(cctx->di, wctx->hmac_ctx, cctx->keylen, key);
}

int
do_hmac(void *walker, uint8_t *data, uint32_t len)
{
	hmac_walker_ctx_t wctx = (hmac_walker_ctx_t)walker;

	cchmac_update(wctx->di, wctx->hmac_ctx, len, data);

	return 0;
}


int
krb5_mic(crypto_ctx_t ctx, gss_buffer_t header, gss_buffer_t bp, gss_buffer_t trailer, uint8_t *mic, int *verify, int ikey, int reverse)
{
	uint8_t digest[ctx->di->output_size];
	cchmac_di_decl(ctx->di, hmac_ctx);
	int kdx = (verify == NULL) ? (reverse ? GSS_RCV : GSS_SND) : (reverse ? GSS_SND : GSS_RCV);
	void *key2use;

	if (ikey) {
		if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
			lck_mtx_lock(ctx->lock);
			if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
				cc_key_schedule_create(ctx);
			}
			ctx->flags |= CRYPTO_KS_ALLOCED;
			lck_mtx_unlock(ctx->lock);
		}
		key2use = ctx->ks.ikey[kdx];
	} else {
		key2use = ctx->ckey[kdx];
	}

	cchmac_init(ctx->di, hmac_ctx, ctx->keylen, key2use);

	if (header) {
		cchmac_update(ctx->di, hmac_ctx, header->length, header->value);
	}

	cchmac_update(ctx->di, hmac_ctx, bp->length, bp->value);

	if (trailer) {
		cchmac_update(ctx->di, hmac_ctx, trailer->length, trailer->value);
	}

	cchmac_final(ctx->di, hmac_ctx, digest);

	if (verify) {
		*verify = (memcmp(mic, digest, ctx->digest_size) == 0);
	} else {
		memcpy(mic, digest, ctx->digest_size);
	}

	return 0;
}

int
krb5_mic_mbuf(crypto_ctx_t ctx, gss_buffer_t header,
    mbuf_t mbp, uint32_t offset, uint32_t len, gss_buffer_t trailer, uint8_t *mic, int *verify, int ikey, int reverse)
{
	struct hmac_walker_ctx wctx;
	uint8_t digest[ctx->di->output_size];
	int error;
	int kdx = (verify == NULL) ? (reverse ? GSS_RCV : GSS_SND) : (reverse ? GSS_SND : GSS_RCV);
	void *key2use;

	if (ikey) {
		if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
			lck_mtx_lock(ctx->lock);
			if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
				cc_key_schedule_create(ctx);
			}
			ctx->flags |= CRYPTO_KS_ALLOCED;
			lck_mtx_unlock(ctx->lock);
		}
		key2use = ctx->ks.ikey[kdx];
	} else {
		key2use = ctx->ckey[kdx];
	}

	do_hmac_init(&wctx, ctx, key2use);

	if (header) {
		cchmac_update(ctx->di, wctx.hmac_ctx, header->length, header->value);
	}

	error = mbuf_walk(mbp, offset, len, 1, do_hmac, &wctx);

	if (error) {
		return error;
	}
	if (trailer) {
		cchmac_update(ctx->di, wctx.hmac_ctx, trailer->length, trailer->value);
	}

	cchmac_final(ctx->di, wctx.hmac_ctx, digest);
	FREE(wctx.hmac_ctx, M_TEMP);

	if (verify) {
		*verify = (memcmp(mic, digest, ctx->digest_size) == 0);
		if (!*verify) {
			return EBADRPC;
		}
	} else {
		memcpy(mic, digest, ctx->digest_size);
	}

	return 0;
}

errno_t
/* __attribute__((optnone)) */
krb5_crypt_mbuf(crypto_ctx_t ctx, mbuf_t *mbp, uint32_t len, int encrypt, cccbc_ctx *ks)
{
	struct crypt_walker_ctx wctx;
	const struct ccmode_cbc *ccmode = encrypt ? ctx->enc_mode : ctx->dec_mode;
	size_t plen = len;
	size_t cts_len = 0;
	mbuf_t mb, lmb;
	int error;

	if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
		lck_mtx_lock(ctx->lock);
		if (!(ctx->flags & CRYPTO_KS_ALLOCED)) {
			cc_key_schedule_create(ctx);
		}
		ctx->flags |= CRYPTO_KS_ALLOCED;
		lck_mtx_unlock(ctx->lock);
	}
	if (!ks) {
		ks = encrypt ? ctx->ks.enc : ctx->ks.dec;
	}

	if ((ctx->flags & CRYPTO_CTS_ENABLE) && ctx->mpad == 1) {
		uint8_t block[ccmode->block_size];
		/* if the length is less than or equal to a blocksize. We just encrypt the block */
		if (len <= ccmode->block_size) {
			if (len < ccmode->block_size) {
				memset(block, 0, sizeof(block));
				gss_append_mbuf(*mbp, block, ccmode->block_size);
			}
			plen = ccmode->block_size;
		} else {
			/* determine where the last two blocks are */
			uint32_t r = len % ccmode->block_size;

			cts_len  = r ? r + ccmode->block_size : 2 * ccmode->block_size;
			plen = len - cts_len;
			/* If plen is 0 we only have two blocks to crypt with ccpad below */
			if (plen == 0) {
				lmb = *mbp;
			} else {
				gss_normalize_mbuf(*mbp, 0, &plen, &mb, &lmb, 0);
				assert(*mbp == mb);
				assert(plen == len - cts_len);
				assert(gss_mbuf_len(mb, 0) == plen);
				assert(gss_mbuf_len(lmb, 0) == cts_len);
			}
		}
	} else if (len % ctx->mpad) {
		uint8_t pad_block[ctx->mpad];
		size_t padlen = ctx->mpad - (len % ctx->mpad);

		memset(pad_block, 0, padlen);
		error = gss_append_mbuf(*mbp, pad_block, padlen);
		if (error) {
			return error;
		}
		plen = len + padlen;
	}
	do_crypt_init(&wctx, encrypt, ctx, ks);
	if (plen) {
		error = mbuf_walk(*mbp, 0, plen, ccmode->block_size, do_crypt, &wctx);
		if (error) {
			return error;
		}
	}

	if ((ctx->flags & CRYPTO_CTS_ENABLE) && cts_len) {
		uint8_t cts_pad[2 * ccmode->block_size];
		ccpad_func do_ccpad = encrypt ? ccpad_cts3_encrypt : ccpad_cts3_decrypt;

		assert(cts_len <= 2 * ccmode->block_size && cts_len > ccmode->block_size);
		memset(cts_pad, 0, sizeof(cts_pad));
		mbuf_copydata(lmb, 0, cts_len, cts_pad);
		mbuf_freem(lmb);
		do_ccpad(ccmode, wctx.crypt_ctx, wctx.iv, cts_len, cts_pad, cts_pad);
		gss_append_mbuf(*mbp, cts_pad, cts_len);
	}
	FREE(wctx.iv, M_TEMP);

	return 0;
}

/*
 * Key derivation routines
 */

static int
rr13(unsigned char *buf, size_t len)
{
	size_t bytes = (len + 7) / 8;
	unsigned char tmp[bytes];
	size_t i;

	if (len == 0) {
		return 0;
	}

	{
		const int bits = 13 % len;
		const int lbit = len % 8;

		memcpy(tmp, buf, bytes);
		if (lbit) {
			/* pad final byte with inital bits */
			tmp[bytes - 1] &= 0xff << (8 - lbit);
			for (i = lbit; i < 8; i += len) {
				tmp[bytes - 1] |= buf[0] >> i;
			}
		}
		for (i = 0; i < bytes; i++) {
			ssize_t bb;
			ssize_t b1, s1, b2, s2;

			/* calculate first bit position of this byte */
			bb = 8 * i - bits;
			while (bb < 0) {
				bb += len;
			}
			/* byte offset and shift count */
			b1 = bb / 8;
			s1 = bb % 8;
			if ((size_t)bb + 8 > bytes * 8) {
				/* watch for wraparound */
				s2 = (len + 8 - s1) % 8;
			} else {
				s2 = 8 - s1;
			}
			b2 = (b1 + 1) % bytes;
			buf[i] = (tmp[b1] << s1) | (tmp[b2] >> s2);
		}
	}
	return 0;
}


/* Add `b' to `a', both being one's complement numbers. */
static void
add1(unsigned char *a, unsigned char *b, size_t len)
{
	ssize_t i;
	int carry = 0;

	for (i = len - 1; i >= 0; i--) {
		int x = a[i] + b[i] + carry;
		carry = x > 0xff;
		a[i] = x & 0xff;
	}
	for (i = len - 1; carry && i >= 0; i--) {
		int x = a[i] + carry;
		carry = x > 0xff;
		a[i] = x & 0xff;
	}
}


static int
krb5_n_fold(const void *instr, size_t len, void *foldstr, size_t size)
{
	/* if len < size we need at most N * len bytes, ie < 2 * size;
	 *  if len > size we need at most 2 * len */
	int ret = 0;
	size_t maxlen = 2 * max(size, len);
	size_t l = 0;
	unsigned char tmp[maxlen];
	unsigned char buf[len];

	memcpy(buf, instr, len);
	memset(foldstr, 0, size);
	do {
		memcpy(tmp + l, buf, len);
		l += len;
		ret = rr13(buf, len * 8);
		if (ret) {
			goto out;
		}
		while (l >= size) {
			add1(foldstr, tmp, size);
			l -= size;
			if (l == 0) {
				break;
			}
			memmove(tmp, tmp + size, l);
		}
	} while (l != 0);
out:

	return ret;
}

void
krb5_make_usage(uint32_t usage_no, uint8_t suffix, uint8_t usage_string[KRB5_USAGE_LEN])
{
	uint32_t i;

	for (i = 0; i < 4; i++) {
		usage_string[i] = ((usage_no >> 8 * (3 - i)) & 0xff);
	}
	usage_string[i] = suffix;
}

void
krb5_key_derivation(crypto_ctx_t ctx, const void *cons, size_t conslen, void **dkey, size_t dklen)
{
	size_t blocksize = ctx->enc_mode->block_size;
	cccbc_iv_decl(blocksize, iv);
	cccbc_ctx_decl(ctx->enc_mode->size, enc_ctx);
	size_t ksize = 8 * dklen;
	size_t nblocks = (ksize + 8 * blocksize - 1) / (8 * blocksize);
	uint8_t *dkptr;
	uint8_t block[blocksize];

	MALLOC(*dkey, void *, nblocks * blocksize, M_TEMP, M_WAITOK | M_ZERO);
	dkptr = *dkey;

	krb5_n_fold(cons, conslen, block, blocksize);
	cccbc_init(ctx->enc_mode, enc_ctx, ctx->keylen, ctx->key);
	for (size_t i = 0; i < nblocks; i++) {
		cccbc_set_iv(ctx->enc_mode, iv, NULL);
		cccbc_update(ctx->enc_mode, enc_ctx, iv, 1, block, block);
		memcpy(dkptr, block, blocksize);
		dkptr += blocksize;
	}
}

static void
des_make_key(const uint8_t rawkey[7], uint8_t deskey[8])
{
	uint8_t val = 0;

	memcpy(deskey, rawkey, 7);
	for (int i = 0; i < 7; i++) {
		val |= ((deskey[i] & 1) << (i + 1));
	}
	deskey[7] = val;
	ccdes_key_set_odd_parity(deskey, 8);
}

static void
krb5_3des_key_derivation(crypto_ctx_t ctx, const void *cons, size_t conslen, void **des3key)
{
	const struct ccmode_cbc *cbcmode = ctx->enc_mode;
	void *rawkey;
	uint8_t *kptr, *rptr;

	MALLOC(*des3key, void *, 3 * cbcmode->block_size, M_TEMP, M_WAITOK | M_ZERO);
	krb5_key_derivation(ctx, cons, conslen, &rawkey, 3 * (cbcmode->block_size - 1));
	kptr = (uint8_t *)*des3key;
	rptr = (uint8_t *)rawkey;

	for (int i = 0; i < 3; i++) {
		des_make_key(rptr, kptr);
		rptr += cbcmode->block_size - 1;
		kptr += cbcmode->block_size;
	}

	cc_clear(3 * (cbcmode->block_size - 1), rawkey);
	FREE(rawkey, M_TEMP);
}

/*
 * Create a key schecule
 *
 */
void
cc_key_schedule_create(crypto_ctx_t ctx)
{
	uint8_t usage_string[KRB5_USAGE_LEN];
	lucid_context_t lctx = ctx->gss_ctx;
	void *ekey;

	switch (lctx->key_data.proto) {
	case 0: {
		if (ctx->ks.enc == NULL) {
			MALLOC(ctx->ks.enc, cccbc_ctx *, ctx->enc_mode->size, M_TEMP, M_WAITOK | M_ZERO);
			cccbc_init(ctx->enc_mode, ctx->ks.enc, ctx->keylen, ctx->key);
		}
		if (ctx->ks.dec == NULL) {
			MALLOC(ctx->ks.dec, cccbc_ctx *, ctx->dec_mode->size, M_TEMP, M_WAITOK | M_ZERO);
			cccbc_init(ctx->dec_mode, ctx->ks.dec, ctx->keylen, ctx->key);
		}
	}
	case 1: {
		if (ctx->ks.enc == NULL) {
			krb5_make_usage(lctx->initiate ?
			    KRB5_USAGE_INITIATOR_SEAL : KRB5_USAGE_ACCEPTOR_SEAL,
			    0xAA, usage_string);
			krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ekey, ctx->keylen);
			MALLOC(ctx->ks.enc, cccbc_ctx *, ctx->enc_mode->size, M_TEMP, M_WAITOK | M_ZERO);
			cccbc_init(ctx->enc_mode, ctx->ks.enc, ctx->keylen, ekey);
			FREE(ekey, M_TEMP);
		}
		if (ctx->ks.dec == NULL) {
			krb5_make_usage(lctx->initiate ?
			    KRB5_USAGE_ACCEPTOR_SEAL : KRB5_USAGE_INITIATOR_SEAL,
			    0xAA, usage_string);
			krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ekey, ctx->keylen);
			MALLOC(ctx->ks.dec, cccbc_ctx *, ctx->dec_mode->size, M_TEMP, M_WAITOK | M_ZERO);
			cccbc_init(ctx->dec_mode, ctx->ks.dec, ctx->keylen, ekey);
			FREE(ekey, M_TEMP);
		}
		if (ctx->ks.ikey[GSS_SND] == NULL) {
			krb5_make_usage(lctx->initiate ?
			    KRB5_USAGE_INITIATOR_SEAL : KRB5_USAGE_ACCEPTOR_SEAL,
			    0x55, usage_string);
			krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ks.ikey[GSS_SND], ctx->keylen);
		}
		if (ctx->ks.ikey[GSS_RCV] == NULL) {
			krb5_make_usage(lctx->initiate ?
			    KRB5_USAGE_ACCEPTOR_SEAL : KRB5_USAGE_INITIATOR_SEAL,
			    0x55, usage_string);
			krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ks.ikey[GSS_RCV], ctx->keylen);
		}
	}
	}
}

void
gss_crypto_ctx_free(crypto_ctx_t ctx)
{
	ctx->ks.ikey[GSS_SND] = NULL;
	if (ctx->ks.ikey[GSS_RCV] && ctx->key != ctx->ks.ikey[GSS_RCV]) {
		cc_clear(ctx->keylen, ctx->ks.ikey[GSS_RCV]);
		FREE(ctx->ks.ikey[GSS_RCV], M_TEMP);
	}
	ctx->ks.ikey[GSS_RCV] = NULL;
	if (ctx->ks.enc) {
		cccbc_ctx_clear(ctx->enc_mode->size, ctx->ks.enc);
		FREE(ctx->ks.enc, M_TEMP);
		ctx->ks.enc = NULL;
	}
	if (ctx->ks.dec) {
		cccbc_ctx_clear(ctx->dec_mode->size, ctx->ks.dec);
		FREE(ctx->ks.dec, M_TEMP);
		ctx->ks.dec = NULL;
	}
	if (ctx->ckey[GSS_SND] && ctx->ckey[GSS_SND] != ctx->key) {
		cc_clear(ctx->keylen, ctx->ckey[GSS_SND]);
		FREE(ctx->ckey[GSS_SND], M_TEMP);
	}
	ctx->ckey[GSS_SND] = NULL;
	if (ctx->ckey[GSS_RCV] && ctx->ckey[GSS_RCV] != ctx->key) {
		cc_clear(ctx->keylen, ctx->ckey[GSS_RCV]);
		FREE(ctx->ckey[GSS_RCV], M_TEMP);
	}
	ctx->ckey[GSS_RCV] = NULL;
	ctx->key = NULL;
	ctx->keylen = 0;
}

int
gss_crypto_ctx_init(struct crypto_ctx *ctx, lucid_context_t lucid)
{
	ctx->gss_ctx = lucid;
	void *key;
	uint8_t usage_string[KRB5_USAGE_LEN];

	ctx->keylen = ctx->gss_ctx->ctx_key.key.key_len;
	key = ctx->gss_ctx->ctx_key.key.key_val;
	ctx->etype = ctx->gss_ctx->ctx_key.etype;
	ctx->key = key;

	switch (ctx->etype) {
	case AES128_CTS_HMAC_SHA1_96:
	case AES256_CTS_HMAC_SHA1_96:
		ctx->enc_mode = ccaes_cbc_encrypt_mode();
		assert(ctx->enc_mode);
		ctx->dec_mode = ccaes_cbc_decrypt_mode();
		assert(ctx->dec_mode);
		ctx->ks.enc = NULL;
		ctx->ks.dec = NULL;
		ctx->di = ccsha1_di();
		assert(ctx->di);
		ctx->flags = CRYPTO_CTS_ENABLE;
		ctx->mpad = 1;
		ctx->digest_size = 12; /* 96 bits */
		krb5_make_usage(ctx->gss_ctx->initiate ?
		    KRB5_USAGE_INITIATOR_SIGN : KRB5_USAGE_ACCEPTOR_SIGN,
		    0x99, usage_string);
		krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ckey[GSS_SND], ctx->keylen);
		krb5_make_usage(ctx->gss_ctx->initiate ?
		    KRB5_USAGE_ACCEPTOR_SIGN : KRB5_USAGE_INITIATOR_SIGN,
		    0x99, usage_string);
		krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ckey[GSS_RCV], ctx->keylen);
		break;
	case DES3_CBC_SHA1_KD:
		ctx->enc_mode = ccdes3_cbc_encrypt_mode();
		assert(ctx->enc_mode);
		ctx->dec_mode = ccdes3_cbc_decrypt_mode();
		assert(ctx->dec_mode);
		ctx->ks.ikey[GSS_SND]  = ctx->key;
		ctx->ks.ikey[GSS_RCV]  = ctx->key;
		ctx->di = ccsha1_di();
		assert(ctx->di);
		ctx->flags = 0;
		ctx->mpad = ctx->enc_mode->block_size;
		ctx->digest_size = 20; /* 160 bits */
		krb5_make_usage(KRB5_USAGE_ACCEPTOR_SIGN, 0x99, usage_string);
		krb5_3des_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ckey[GSS_SND]);
		krb5_3des_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ctx->ckey[GSS_RCV]);
		break;
	default:
		return ENOTSUP;
	}

	ctx->lock = lck_mtx_alloc_init(gss_krb5_mech_grp, LCK_ATTR_NULL);

	return 0;
}

/*
 * CFX gss support routines
 */
/* From Heimdal cfx.h file RFC 4121 Cryptoo framework extensions */
typedef struct gss_cfx_mic_token_desc_struct {
	uint8_t TOK_ID[2];      /* 04 04 */
	uint8_t Flags;
	uint8_t Filler[5];
	uint8_t SND_SEQ[8];
} gss_cfx_mic_token_desc, *gss_cfx_mic_token;

typedef struct gss_cfx_wrap_token_desc_struct {
	uint8_t TOK_ID[2];      /* 05 04 */
	uint8_t Flags;
	uint8_t Filler;
	uint8_t EC[2];
	uint8_t RRC[2];
	uint8_t SND_SEQ[8];
} gss_cfx_wrap_token_desc, *gss_cfx_wrap_token;

/* End of cfx.h file */

#define CFXSentByAcceptor       (1 << 0)
#define CFXSealed               (1 << 1)
#define CFXAcceptorSubkey       (1 << 2)

const gss_cfx_mic_token_desc mic_cfx_token = {
	.TOK_ID = "\x04\x04",
	.Flags = 0,
	.Filler = "\xff\xff\xff\xff\xff",
	.SND_SEQ = "\x00\x00\x00\x00\x00\x00\x00\x00"
};

const gss_cfx_wrap_token_desc wrap_cfx_token = {
	.TOK_ID = "\x05\04",
	.Flags = 0,
	.Filler = '\xff',
	.EC = "\x00\x00",
	.RRC = "\x00\x00",
	.SND_SEQ = "\x00\x00\x00\x00\x00\x00\x00\x00"
};

static int
gss_krb5_cfx_verify_mic_token(gss_ctx_id_t ctx, gss_cfx_mic_token token)
{
	int i;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	uint8_t flags = 0;

	if (token->TOK_ID[0] != mic_cfx_token.TOK_ID[0] || token->TOK_ID[1] != mic_cfx_token.TOK_ID[1]) {
		printf("Bad mic TOK_ID %x %x\n", token->TOK_ID[0], token->TOK_ID[1]);
		return EBADRPC;
	}
	if (lctx->initiate) {
		flags |= CFXSentByAcceptor;
	}
	if (lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey) {
		flags |= CFXAcceptorSubkey;
	}
	if (token->Flags != flags) {
		printf("Bad flags received %x exptect %x\n", token->Flags, flags);
		return EBADRPC;
	}
	for (i = 0; i < 5; i++) {
		if (token->Filler[i] != mic_cfx_token.Filler[i]) {
			break;
		}
	}

	if (i != 5) {
		printf("Bad mic filler %x @ %d\n", token->Filler[i], i);
		return EBADRPC;
	}

	return 0;
}

uint32_t
gss_krb5_cfx_get_mic(uint32_t *minor,           /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    gss_qop_t qop __unused,                     /* qop_req (ignored) */
    gss_buffer_t mbp,                           /* message mbuf */
    gss_buffer_t mic /* message_token */)
{
	gss_cfx_mic_token_desc token;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	gss_buffer_desc header;
	uint32_t rv;
	uint64_t seq = htonll(lctx->send_seq);

	if (minor == NULL) {
		minor = &rv;
	}
	*minor = 0;
	token = mic_cfx_token;
	mic->length = sizeof(token) + cctx->digest_size;
	MALLOC(mic->value, void *, mic->length, M_TEMP, M_WAITOK | M_ZERO);
	if (!lctx->initiate) {
		token.Flags |= CFXSentByAcceptor;
	}
	if (lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey) {
		token.Flags |= CFXAcceptorSubkey;
	}
	memcpy(&token.SND_SEQ, &seq, sizeof(lctx->send_seq));
	lctx->send_seq++; //XXX should only update this below on success? Heimdal seems to do it this way
	header.value = &token;
	header.length = sizeof(gss_cfx_mic_token_desc);

	*minor = krb5_mic(cctx, NULL, mbp, &header, (uint8_t *)mic->value + sizeof(token), NULL, 0, 0);

	if (*minor) {
		mic->length = 0;
		FREE(mic->value, M_TEMP);
		mic->value = NULL;
	} else {
		memcpy(mic->value, &token, sizeof(token));
	}

	return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

uint32_t
gss_krb5_cfx_verify_mic(uint32_t *minor,        /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    gss_buffer_t mbp,                           /* message_buffer */
    gss_buffer_t mic,                           /* message_token */
    gss_qop_t *qop /* qop_state */)
{
	gss_cfx_mic_token token = mic->value;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint8_t *digest = (uint8_t *)mic->value + sizeof(gss_cfx_mic_token_desc);
	int verified = 0;
	uint64_t seq;
	uint32_t rv;
	gss_buffer_desc header;

	if (qop) {
		*qop = GSS_C_QOP_DEFAULT;
	}
	if (minor == NULL) {
		minor = &rv;
	}

	if (mic->length != sizeof(gss_cfx_mic_token_desc) + cctx->digest_size) {
		printf("mic token wrong length\n");
		*minor = EBADRPC;
		goto out;
	}
	*minor = gss_krb5_cfx_verify_mic_token(ctx, token);
	if (*minor) {
		return GSS_S_FAILURE;
	}
	header.value = token;
	header.length = sizeof(gss_cfx_mic_token_desc);
	*minor = krb5_mic(cctx, NULL, mbp, &header, digest, &verified, 0, 0);

	if (verified) {
		//XXX  errors and such? Sequencing and replay? Not supported in RPCSEC_GSS
		memcpy(&seq, token->SND_SEQ, sizeof(uint64_t));
		seq = ntohll(seq);
		lctx->recv_seq = seq;
	}

out:
	return verified ? GSS_S_COMPLETE : GSS_S_BAD_SIG;
}

uint32_t
gss_krb5_cfx_get_mic_mbuf(uint32_t *minor,      /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    gss_qop_t qop __unused,                       /* qop_req (ignored) */
    mbuf_t mbp,                         /* message mbuf */
    size_t offset,                              /* offest */
    size_t len,                         /* length */
    gss_buffer_t mic /* message_token */)
{
	gss_cfx_mic_token_desc token;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint32_t rv;
	uint64_t seq = htonll(lctx->send_seq);
	gss_buffer_desc header;

	if (minor == NULL) {
		minor = &rv;
	}
	*minor = 0;

	token = mic_cfx_token;
	mic->length = sizeof(token) + cctx->digest_size;
	MALLOC(mic->value, void *, mic->length, M_TEMP, M_WAITOK | M_ZERO);
	if (!lctx->initiate) {
		token.Flags |= CFXSentByAcceptor;
	}
	if (lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey) {
		token.Flags |= CFXAcceptorSubkey;
	}

	memcpy(&token.SND_SEQ, &seq, sizeof(lctx->send_seq));
	lctx->send_seq++; //XXX should only update this below on success? Heimdal seems to do it this way

	header.length = sizeof(token);
	header.value = &token;

	len = len ? len : gss_mbuf_len(mbp, offset);
	*minor = krb5_mic_mbuf(cctx, NULL, mbp, offset, len, &header, (uint8_t *)mic->value + sizeof(token), NULL, 0, 0);

	if (*minor) {
		mic->length = 0;
		FREE(mic->value, M_TEMP);
		mic->value = NULL;
	} else {
		memcpy(mic->value, &token, sizeof(token));
	}

	return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}


uint32_t
gss_krb5_cfx_verify_mic_mbuf(uint32_t *minor,   /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    mbuf_t mbp,                                         /* message_buffer */
    size_t offset,                                      /* offset */
    size_t len,                                         /* length */
    gss_buffer_t mic,                           /* message_token */
    gss_qop_t *qop /* qop_state */)
{
	gss_cfx_mic_token token = mic->value;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint8_t *digest = (uint8_t *)mic->value + sizeof(gss_cfx_mic_token_desc);
	int verified;
	uint64_t seq;
	uint32_t rv;
	gss_buffer_desc header;

	if (qop) {
		*qop = GSS_C_QOP_DEFAULT;
	}

	if (minor == NULL) {
		minor = &rv;
	}

	*minor = gss_krb5_cfx_verify_mic_token(ctx, token);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	header.length = sizeof(gss_cfx_mic_token_desc);
	header.value = mic->value;

	*minor = krb5_mic_mbuf(cctx, NULL, mbp, offset, len, &header, digest, &verified, 0, 0);

	//XXX  errors and such? Sequencing and replay? Not Supported RPCSEC_GSS
	memcpy(&seq, token->SND_SEQ, sizeof(uint64_t));
	seq = ntohll(seq);
	lctx->recv_seq = seq;

	return verified ? GSS_S_COMPLETE : GSS_S_BAD_SIG;
}

errno_t
krb5_cfx_crypt_mbuf(crypto_ctx_t ctx, mbuf_t *mbp, size_t *len, int encrypt, int reverse)
{
	const struct ccmode_cbc *ccmode = encrypt ? ctx->enc_mode : ctx->dec_mode;
	uint8_t confounder[ccmode->block_size];
	uint8_t digest[ctx->digest_size];
	size_t tlen, r = 0;
	errno_t error;

	if (encrypt) {
		read_random(confounder, ccmode->block_size);
		error = gss_prepend_mbuf(mbp, confounder, ccmode->block_size);
		if (error) {
			return error;
		}
		tlen = *len + ccmode->block_size;
		if (ctx->mpad > 1) {
			r = ctx->mpad - (tlen % ctx->mpad);
		}
		/* We expect that r == 0 from krb5_cfx_wrap */
		if (r != 0) {
			uint8_t mpad[r];
			memset(mpad, 0, r);
			error = gss_append_mbuf(*mbp, mpad, r);
			if (error) {
				return error;
			}
		}
		tlen += r;
		error = krb5_mic_mbuf(ctx, NULL, *mbp, 0, tlen, NULL, digest, NULL, 1, 0);
		if (error) {
			return error;
		}
		error = krb5_crypt_mbuf(ctx, mbp, tlen, 1, NULL);
		if (error) {
			return error;
		}
		error = gss_append_mbuf(*mbp, digest, ctx->digest_size);
		if (error) {
			return error;
		}
		*len = tlen + ctx->digest_size;
		return 0;
	} else {
		int verf;
		cccbc_ctx *ks = NULL;

		if (*len < ctx->digest_size + sizeof(confounder)) {
			return EBADRPC;
		}
		tlen = *len - ctx->digest_size;
		/* get the digest */
		error = mbuf_copydata(*mbp, tlen, ctx->digest_size, digest);
		/* Remove the digest from the mbuffer */
		error = gss_strip_mbuf(*mbp, -ctx->digest_size);
		if (error) {
			return error;
		}

		if (reverse) {
			/*
			 * Derive a key schedule that the sender can unwrap with. This
			 * is so that RPCSEC_GSS can restore encrypted arguments for
			 * resending. We do that because the RPCSEC_GSS sequence number in
			 * the rpc header is prepended to the body of the message before wrapping.
			 */
			void *ekey;
			uint8_t usage_string[KRB5_USAGE_LEN];
			lucid_context_t lctx = ctx->gss_ctx;

			krb5_make_usage(lctx->initiate ?
			    KRB5_USAGE_INITIATOR_SEAL : KRB5_USAGE_ACCEPTOR_SEAL,
			    0xAA, usage_string);
			krb5_key_derivation(ctx, usage_string, KRB5_USAGE_LEN, &ekey, ctx->keylen);
			MALLOC(ks, cccbc_ctx *, ctx->dec_mode->size, M_TEMP, M_WAITOK | M_ZERO);
			cccbc_init(ctx->dec_mode, ks, ctx->keylen, ekey);
			FREE(ekey, M_TEMP);
		}
		error = krb5_crypt_mbuf(ctx, mbp, tlen, 0, ks);
		FREE(ks, M_TEMP);
		if (error) {
			return error;
		}
		error = krb5_mic_mbuf(ctx, NULL, *mbp, 0, tlen, NULL, digest, &verf, 1, reverse);
		if (error) {
			return error;
		}
		if (!verf) {
			return EBADRPC;
		}
		/* strip off the confounder */
		error = gss_strip_mbuf(*mbp, ccmode->block_size);
		if (error) {
			return error;
		}
		*len = tlen - ccmode->block_size;
	}
	return 0;
}

uint32_t
gss_krb5_cfx_wrap_mbuf(uint32_t *minor,         /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    int conf_flag,                              /* conf_req_flag */
    gss_qop_t qop __unused,                     /* qop_req */
    mbuf_t *mbp,                                /* input/output message_buffer */
    size_t len,                                 /* mbuf chain length */
    int *conf /* conf_state */)
{
	gss_cfx_wrap_token_desc token;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	int error = 0;
	uint32_t mv;
	uint64_t seq = htonll(lctx->send_seq);

	if (minor == NULL) {
		minor = &mv;
	}
	if (conf) {
		*conf = conf_flag;
	}

	*minor = 0;
	token = wrap_cfx_token;
	if (!lctx->initiate) {
		token.Flags |= CFXSentByAcceptor;
	}
	if (lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey) {
		token.Flags |= CFXAcceptorSubkey;
	}
	memcpy(&token.SND_SEQ, &seq, sizeof(uint64_t));
	lctx->send_seq++;
	if (conf_flag) {
		uint8_t pad[cctx->mpad];
		uint16_t plen = 0;

		token.Flags |= CFXSealed;
		memset(pad, 0, cctx->mpad);
		if (cctx->mpad > 1) {
			plen = htons(cctx->mpad - ((len + sizeof(gss_cfx_wrap_token_desc)) % cctx->mpad));
			token.EC[0] = ((plen >> 8) & 0xff);
			token.EC[1] = (plen & 0xff);
		}
		if (plen) {
			error = gss_append_mbuf(*mbp, pad, plen);
			len += plen;
		}
		if (error == 0) {
			error = gss_append_mbuf(*mbp, (uint8_t *)&token, sizeof(gss_cfx_wrap_token_desc));
			len += sizeof(gss_cfx_wrap_token_desc);
		}
		if (error == 0) {
			error = krb5_cfx_crypt_mbuf(cctx, mbp, &len, 1, 0);
		}
		if (error == 0) {
			error = gss_prepend_mbuf(mbp, (uint8_t *)&token, sizeof(gss_cfx_wrap_token_desc));
		}
	} else {
		uint8_t digest[cctx->digest_size];
		gss_buffer_desc header;

		header.length = sizeof(token);
		header.value = &token;

		error = krb5_mic_mbuf(cctx, NULL, *mbp, 0, len, &header, digest, NULL, 1, 0);
		if (error == 0) {
			error = gss_append_mbuf(*mbp, digest, cctx->digest_size);
			if (error == 0) {
				uint16_t plen = htons(cctx->digest_size);
				memcpy(token.EC, &plen, 2);
				error = gss_prepend_mbuf(mbp, (uint8_t *)&token, sizeof(gss_cfx_wrap_token_desc));
			}
		}
	}
	if (error) {
		*minor = error;
		return GSS_S_FAILURE;
	}

	return GSS_S_COMPLETE;
}

/*
 * Given a wrap token the has a rrc, move the trailer back to the end.
 */
static void
gss_krb5_cfx_unwrap_rrc_mbuf(mbuf_t header, size_t rrc)
{
	mbuf_t body, trailer;

	gss_normalize_mbuf(header, sizeof(gss_cfx_wrap_token_desc), &rrc, &trailer, &body, 0);
	gss_join_mbuf(header, body, trailer);
}

uint32_t
gss_krb5_cfx_unwrap_mbuf(uint32_t * minor,      /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    mbuf_t *mbp,                                /* input/output message_buffer */
    size_t len,                                 /* mbuf chain length */
    int *conf_flag,                             /* conf_state */
    gss_qop_t *qop /* qop state */)
{
	gss_cfx_wrap_token_desc token;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	int error, conf;
	uint16_t ec = 0, rrc = 0;
	uint64_t seq;
	int reverse = (*qop == GSS_C_QOP_REVERSE);
	int initiate = lctx->initiate ? (reverse ? 0 : 1) : (reverse ? 1 : 0);

	error = mbuf_copydata(*mbp, 0, sizeof(gss_cfx_wrap_token_desc), &token);
	gss_strip_mbuf(*mbp, sizeof(gss_cfx_wrap_token_desc));
	len -= sizeof(gss_cfx_wrap_token_desc);

	/* Check for valid token */
	if (token.TOK_ID[0] != wrap_cfx_token.TOK_ID[0] ||
	    token.TOK_ID[1] != wrap_cfx_token.TOK_ID[1] ||
	    token.Filler != wrap_cfx_token.Filler) {
		printf("Token id does not match\n");
		goto badrpc;
	}
	if ((initiate && !(token.Flags & CFXSentByAcceptor)) ||
	    (lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey && !(token.Flags & CFXAcceptorSubkey))) {
		printf("Bad flags %x\n", token.Flags);
		goto badrpc;
	}

	/* XXX Sequence replay detection */
	memcpy(&seq, token.SND_SEQ, sizeof(seq));
	seq = ntohll(seq);
	lctx->recv_seq = seq;

	ec = (token.EC[0] << 8) | token.EC[1];
	rrc = (token.RRC[0] << 8) | token.RRC[1];
	*qop = GSS_C_QOP_DEFAULT;
	conf = ((token.Flags & CFXSealed) == CFXSealed);
	if (conf_flag) {
		*conf_flag = conf;
	}
	if (conf) {
		gss_cfx_wrap_token_desc etoken;

		if (rrc) { /* Handle Right rotation count */
			gss_krb5_cfx_unwrap_rrc_mbuf(*mbp, rrc);
		}
		error = krb5_cfx_crypt_mbuf(cctx, mbp, &len, 0, reverse);
		if (error) {
			printf("krb5_cfx_crypt_mbuf %d\n", error);
			*minor = error;
			return GSS_S_FAILURE;
		}
		if (len >= sizeof(gss_cfx_wrap_token_desc)) {
			len -= sizeof(gss_cfx_wrap_token_desc);
		} else {
			goto badrpc;
		}
		mbuf_copydata(*mbp, len, sizeof(gss_cfx_wrap_token_desc), &etoken);
		/* Verify etoken with the token wich should be the same, except the rc field is always zero */
		token.RRC[0] = token.RRC[1] = 0;
		if (memcmp(&token, &etoken, sizeof(gss_cfx_wrap_token_desc)) != 0) {
			printf("Encrypted token mismach\n");
			goto badrpc;
		}
		/* strip the encrypted token and any pad bytes */
		gss_strip_mbuf(*mbp, -(sizeof(gss_cfx_wrap_token_desc) + ec));
		len -= (sizeof(gss_cfx_wrap_token_desc) + ec);
	} else {
		uint8_t digest[cctx->digest_size];
		int verf;
		gss_buffer_desc header;

		if (ec != cctx->digest_size || len >= cctx->digest_size) {
			goto badrpc;
		}
		len -= cctx->digest_size;
		mbuf_copydata(*mbp, len, cctx->digest_size, digest);
		gss_strip_mbuf(*mbp, -cctx->digest_size);
		/* When calculating the mic header fields ec and rcc must be zero */
		token.EC[0] = token.EC[1] = token.RRC[0] = token.RRC[1] = 0;
		header.value = &token;
		header.length = sizeof(gss_cfx_wrap_token_desc);
		error = krb5_mic_mbuf(cctx, NULL, *mbp, 0, len, &header, digest, &verf, 1, reverse);
		if (error) {
			goto badrpc;
		}
	}
	return GSS_S_COMPLETE;

badrpc:
	*minor = EBADRPC;
	return GSS_S_FAILURE;
}

/*
 * RFC 1964 3DES support
 */

typedef struct gss_1964_mic_token_desc_struct {
	uint8_t TOK_ID[2];      /* 01 01 */
	uint8_t Sign_Alg[2];
	uint8_t Filler[4];      /* ff ff ff ff */
} gss_1964_mic_token_desc, *gss_1964_mic_token;

typedef struct gss_1964_wrap_token_desc_struct {
	uint8_t TOK_ID[2];      /* 02 01 */
	uint8_t Sign_Alg[2];
	uint8_t Seal_Alg[2];
	uint8_t Filler[2];      /* ff ff */
} gss_1964_wrap_token_desc, *gss_1964_wrap_token;

typedef struct gss_1964_delete_token_desc_struct {
	uint8_t TOK_ID[2];      /* 01 02 */
	uint8_t Sign_Alg[2];
	uint8_t Filler[4];      /* ff ff ff ff */
} gss_1964_delete_token_desc, *gss_1964_delete_token;

typedef struct gss_1964_header_desc_struct {
	uint8_t App0;           /* 0x60 Application 0 constructed */
	uint8_t AppLen[];       /* Variable Der length */
} gss_1964_header_desc, *gss_1964_header;

typedef union {
	gss_1964_mic_token_desc         mic_tok;
	gss_1964_wrap_token_desc        wrap_tok;
	gss_1964_delete_token_desc      del_tok;
} gss_1964_tok_type __attribute__((transparent_union));

typedef struct gss_1964_token_body_struct {
	uint8_t OIDType;        /* 0x06 */
	uint8_t OIDLen;         /* 0x09 */
	uint8_t kerb_mech[9];   /* Der Encode kerberos mech 1.2.840.113554.1.2.2
	                         *  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 */
	gss_1964_tok_type body;
	uint8_t SND_SEQ[8];
	uint8_t Hash[];         /* Mic */
} gss_1964_token_body_desc, *gss_1964_token_body;


gss_1964_header_desc tok_1964_header = {
	.App0 = 0x60
};

gss_1964_mic_token_desc mic_1964_token = {
	.TOK_ID = "\x01\x01",
	.Filler = "\xff\xff\xff\xff"
};

gss_1964_wrap_token_desc wrap_1964_token = {
	.TOK_ID = "\x02\x01",
	.Filler = "\xff\xff"
};

gss_1964_delete_token_desc del_1964_token = {
	.TOK_ID = "\x01\x01",
	.Filler = "\xff\xff\xff\xff"
};

gss_1964_token_body_desc body_1964_token = {
	.OIDType = 0x06,
	.OIDLen = 0x09,
	.kerb_mech = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02",
};

#define GSS_KRB5_3DES_MAXTOKSZ (sizeof(gss_1964_header_desc) + 5 /* max der length supported */ + sizeof(gss_1964_token_body_desc))

uint32_t gss_krb5_3des_get_mic(uint32_t *, gss_ctx_id_t, gss_qop_t, gss_buffer_t, gss_buffer_t);
uint32_t gss_krb5_3des_verify_mic(uint32_t *, gss_ctx_id_t, gss_buffer_t, gss_buffer_t, gss_qop_t *);
uint32_t gss_krb5_3des_get_mic_mbuf(uint32_t *, gss_ctx_id_t, gss_qop_t, mbuf_t, size_t, size_t, gss_buffer_t);
uint32_t gss_krb5_3des_verify_mic_mbuf(uint32_t *, gss_ctx_id_t, mbuf_t, size_t, size_t, gss_buffer_t, gss_qop_t *);
uint32_t gss_krb5_3des_wrap_mbuf(uint32_t *, gss_ctx_id_t, int, gss_qop_t, mbuf_t *, size_t, int *);
uint32_t gss_krb5_3des_unwrap_mbuf(uint32_t *, gss_ctx_id_t, mbuf_t *, size_t, int *, gss_qop_t *);

/*
 * Decode an ASN.1 DER length field
 */
static ssize_t
gss_krb5_der_length_get(uint8_t **pp)
{
	uint8_t *p = *pp;
	uint32_t flen, len = 0;

	flen = *p & 0x7f;

	if (*p++ & 0x80) {
		if (flen > sizeof(uint32_t)) {
			return -1;
		}
		while (flen--) {
			len = (len << 8) + *p++;
		}
	} else {
		len = flen;
	}
	*pp = p;
	return len;
}

/*
 * Determine size of ASN.1 DER length
 */
static int
gss_krb5_der_length_size(int len)
{
	return
	        len < (1 <<  7) ? 1 :
	        len < (1 <<  8) ? 2 :
	        len < (1 << 16) ? 3 :
	        len < (1 << 24) ? 4 : 5;
}

/*
 * Encode an ASN.1 DER length field
 */
static void
gss_krb5_der_length_put(uint8_t **pp, int len)
{
	int sz = gss_krb5_der_length_size(len);
	uint8_t *p = *pp;

	if (sz == 1) {
		*p++ = (uint8_t) len;
	} else {
		*p++ = (uint8_t) ((sz - 1) | 0x80);
		sz -= 1;
		while (sz--) {
			*p++ = (uint8_t) ((len >> (sz * 8)) & 0xff);
		}
	}

	*pp = p;
}

static void
gss_krb5_3des_token_put(gss_ctx_id_t ctx, gss_1964_tok_type body, gss_buffer_t hash, size_t datalen, gss_buffer_t des3_token)
{
	gss_1964_header token;
	gss_1964_token_body tokbody;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint32_t seq = (uint32_t) (lctx->send_seq++ & 0xffff);
	size_t toklen = sizeof(gss_1964_token_body_desc)  + cctx->digest_size;
	size_t alloclen = toklen + sizeof(gss_1964_header_desc) + gss_krb5_der_length_size(toklen + datalen);
	uint8_t *tokptr;

	MALLOC(token, gss_1964_header, alloclen, M_TEMP, M_WAITOK | M_ZERO);
	*token = tok_1964_header;
	tokptr = token->AppLen;
	gss_krb5_der_length_put(&tokptr, toklen + datalen);
	tokbody = (gss_1964_token_body)tokptr;
	*tokbody = body_1964_token;  /* Initalize the token body */
	tokbody->body = body;  /* and now set the body to the token type passed in */
	seq = htonl(seq);
	for (int i = 0; i < 4; i++) {
		tokbody->SND_SEQ[i] = (uint8_t)((seq >> (i * 8)) & 0xff);
	}
	for (int i = 4; i < 8; i++) {
		tokbody->SND_SEQ[i] = lctx->initiate ? 0x00 : 0xff;
	}

	size_t blocksize = cctx->enc_mode->block_size;
	cccbc_iv_decl(blocksize, iv);
	cccbc_ctx_decl(cctx->enc_mode->size, enc_ctx);
	cccbc_set_iv(cctx->enc_mode, iv, hash->value);
	cccbc_init(cctx->enc_mode, enc_ctx, cctx->keylen, cctx->key);
	cccbc_update(cctx->enc_mode, enc_ctx, iv, 1, tokbody->SND_SEQ, tokbody->SND_SEQ);

	assert(hash->length == cctx->digest_size);
	memcpy(tokbody->Hash, hash->value, hash->length);
	des3_token->length = alloclen;
	des3_token->value = token;
}

static int
gss_krb5_3des_token_get(gss_ctx_id_t ctx, gss_buffer_t intok,
    gss_1964_tok_type body, gss_buffer_t hash, size_t *offset, size_t *len, int reverse)
{
	gss_1964_header token = intok->value;
	gss_1964_token_body tokbody;
	lucid_context_t lctx = &ctx->gss_lucid_ctx;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	ssize_t length;
	size_t toklen;
	uint8_t *tokptr;
	uint32_t seq;
	int initiate;

	if (token->App0 != tok_1964_header.App0) {
		printf("%s: bad framing\n", __func__);
		printgbuf(__func__, intok);
		return EBADRPC;
	}
	tokptr = token->AppLen;
	length = gss_krb5_der_length_get(&tokptr);
	if (length < 0) {
		printf("%s: invalid length\n", __func__);
		printgbuf(__func__, intok);
		return EBADRPC;
	}
	toklen = sizeof(gss_1964_header_desc) + gss_krb5_der_length_size(length)
	    + sizeof(gss_1964_token_body_desc);

	if (intok->length < toklen + cctx->digest_size) {
		printf("%s: token to short", __func__);
		printf("toklen = %d, length = %d\n", (int)toklen, (int)length);
		printgbuf(__func__, intok);
		return EBADRPC;
	}

	if (offset) {
		*offset = toklen + cctx->digest_size;
	}

	if (len) {
		*len = length - sizeof(gss_1964_token_body_desc) - cctx->digest_size;
	}

	tokbody = (gss_1964_token_body)tokptr;
	if (tokbody->OIDType != body_1964_token.OIDType ||
	    tokbody->OIDLen != body_1964_token.OIDLen ||
	    memcmp(tokbody->kerb_mech, body_1964_token.kerb_mech, tokbody->OIDLen) != 0) {
		printf("%s: Invalid mechanism\n", __func__);
		printgbuf(__func__, intok);
		return EBADRPC;
	}
	if (memcmp(&tokbody->body, &body, sizeof(gss_1964_tok_type)) != 0) {
		printf("%s: Invalid body\n", __func__);
		printgbuf(__func__, intok);
		return EBADRPC;
	}
	size_t blocksize = cctx->enc_mode->block_size;
	uint8_t *block = tokbody->SND_SEQ;

	assert(blocksize == sizeof(tokbody->SND_SEQ));
	cccbc_iv_decl(blocksize, iv);
	cccbc_ctx_decl(cctx->dec_mode->size, dec_ctx);
	cccbc_set_iv(cctx->dec_mode, iv, tokbody->Hash);
	cccbc_init(cctx->dec_mode, dec_ctx, cctx->keylen, cctx->key);
	cccbc_update(cctx->dec_mode, dec_ctx, iv, 1, block, block);

	initiate = lctx->initiate ? (reverse ? 0 : 1) : (reverse ? 1 : 0);
	for (int i = 4; i < 8; i++) {
		if (tokbody->SND_SEQ[i] != (initiate ? 0xff : 0x00)) {
			printf("%s: Invalid des mac\n", __func__);
			printgbuf(__func__, intok);
			return EAUTH;
		}
	}

	memcpy(&seq, tokbody->SND_SEQ, sizeof(uint32_t));

	lctx->recv_seq = ntohl(seq);

	assert(hash->length >= cctx->digest_size);
	memcpy(hash->value, tokbody->Hash, cctx->digest_size);

	return 0;
}

uint32_t
gss_krb5_3des_get_mic(uint32_t *minor,          /* minor status */
    gss_ctx_id_t ctx,                           /* krb5 context id */
    gss_qop_t qop __unused,                     /* qop_req (ignored) */
    gss_buffer_t mbp,                           /* message buffer in */
    gss_buffer_t mic)                           /* mic token out */
{
	gss_1964_mic_token_desc tokbody = mic_1964_token;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	gss_buffer_desc hash;
	gss_buffer_desc header;
	uint8_t hashval[cctx->digest_size];

	hash.length = cctx->digest_size;
	hash.value = hashval;
	tokbody.Sign_Alg[0] = 0x04; /* lctx->keydata.lucid_protocol_u.data_1964.sign_alg */
	tokbody.Sign_Alg[1] = 0x00;
	header.length = sizeof(gss_1964_mic_token_desc);
	header.value = &tokbody;

	/* Hash the data */
	*minor = krb5_mic(cctx, &header, mbp, NULL, hashval, NULL, 0, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Make the token */
	gss_krb5_3des_token_put(ctx, tokbody, &hash, 0, mic);

	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_3des_verify_mic(uint32_t *minor,
    gss_ctx_id_t ctx,
    gss_buffer_t mbp,
    gss_buffer_t mic,
    gss_qop_t *qop)
{
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint8_t hashval[cctx->digest_size];
	gss_buffer_desc hash;
	gss_1964_mic_token_desc mtok = mic_1964_token;
	gss_buffer_desc header;
	int verf;

	mtok.Sign_Alg[0] = 0x04; /* lctx->key_data.lucid_protocol_u.data_1964.sign_alg */
	mtok.Sign_Alg[1] = 0x00;
	hash.length = cctx->digest_size;
	hash.value = hashval;
	header.length = sizeof(gss_1964_mic_token_desc);
	header.value = &mtok;

	if (qop) {
		*qop = GSS_C_QOP_DEFAULT;
	}

	*minor = gss_krb5_3des_token_get(ctx, mic, mtok, &hash, NULL, NULL, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	*minor = krb5_mic(cctx, &header, mbp, NULL, hashval, &verf, 0, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	return verf ? GSS_S_COMPLETE : GSS_S_BAD_SIG;
}

uint32_t
gss_krb5_3des_get_mic_mbuf(uint32_t *minor,
    gss_ctx_id_t ctx,
    gss_qop_t qop __unused,
    mbuf_t mbp,
    size_t offset,
    size_t len,
    gss_buffer_t mic)
{
	gss_1964_mic_token_desc tokbody = mic_1964_token;
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	gss_buffer_desc header;
	gss_buffer_desc hash;
	uint8_t hashval[cctx->digest_size];

	hash.length = cctx->digest_size;
	hash.value = hashval;
	tokbody.Sign_Alg[0] = 0x04; /* lctx->key_data.lucid_protocol_u.data_4121.sign_alg */
	tokbody.Sign_Alg[1] = 0x00;
	header.length = sizeof(gss_1964_mic_token_desc);
	header.value = &tokbody;

	/* Hash the data */
	*minor = krb5_mic_mbuf(cctx, &header, mbp, offset, len, NULL, hashval, NULL, 0, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Make the token */
	gss_krb5_3des_token_put(ctx, tokbody, &hash, 0, mic);

	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_3des_verify_mic_mbuf(uint32_t *minor,
    gss_ctx_id_t ctx,
    mbuf_t mbp,
    size_t offset,
    size_t len,
    gss_buffer_t mic,
    gss_qop_t *qop)
{
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	uint8_t hashval[cctx->digest_size];
	gss_buffer_desc header;
	gss_buffer_desc hash;
	gss_1964_mic_token_desc mtok = mic_1964_token;
	int verf;

	mtok.Sign_Alg[0] = 0x04; /* lctx->key_data.lucic_protocol_u.data1964.sign_alg */
	mtok.Sign_Alg[1] = 0x00;
	hash.length = cctx->digest_size;
	hash.value = hashval;
	header.length = sizeof(gss_1964_mic_token_desc);
	header.value = &mtok;

	if (qop) {
		*qop = GSS_C_QOP_DEFAULT;
	}

	*minor = gss_krb5_3des_token_get(ctx, mic, mtok, &hash, NULL, NULL, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	*minor = krb5_mic_mbuf(cctx, &header, mbp, offset, len, NULL, hashval, &verf, 0, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	return verf ? GSS_S_COMPLETE : GSS_S_BAD_SIG;
}

uint32_t
gss_krb5_3des_wrap_mbuf(uint32_t *minor,
    gss_ctx_id_t ctx,
    int conf_flag,
    gss_qop_t qop __unused,
    mbuf_t *mbp,
    size_t len,
    int *conf_state)
{
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	const struct ccmode_cbc *ccmode = cctx->enc_mode;
	uint8_t padlen;
	uint8_t pad[8];
	uint8_t confounder[ccmode->block_size];
	gss_1964_wrap_token_desc tokbody = wrap_1964_token;
	gss_buffer_desc header;
	gss_buffer_desc mic;
	gss_buffer_desc hash;
	uint8_t hashval[cctx->digest_size];

	if (conf_state) {
		*conf_state = conf_flag;
	}

	hash.length = cctx->digest_size;
	hash.value = hashval;
	tokbody.Sign_Alg[0] = 0x04; /* lctx->key_data.lucid_protocol_u.data_1964.sign_alg */
	tokbody.Sign_Alg[1] = 0x00;
	/* conf_flag ? lctx->key_data.lucid_protocol_u.data_1964.seal_alg : 0xffff */
	tokbody.Seal_Alg[0] = conf_flag ? 0x02 : 0xff;
	tokbody.Seal_Alg[1] = conf_flag ? 0x00 : 0xff;
	header.length = sizeof(gss_1964_wrap_token_desc);
	header.value = &tokbody;

	/* Prepend confounder */
	read_random(confounder, ccmode->block_size);
	*minor = gss_prepend_mbuf(mbp, confounder, ccmode->block_size);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Append trailer of up to 8 bytes and set pad length in each trailer byte */
	padlen = 8 - len % 8;
	for (int i = 0; i < padlen; i++) {
		pad[i] = padlen;
	}
	*minor = gss_append_mbuf(*mbp, pad, padlen);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	len += ccmode->block_size + padlen;

	/* Hash the data */
	*minor = krb5_mic_mbuf(cctx, &header, *mbp, 0, len, NULL, hashval, NULL, 0, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Make the token */
	gss_krb5_3des_token_put(ctx, tokbody, &hash, len, &mic);

	if (conf_flag) {
		*minor = krb5_crypt_mbuf(cctx, mbp, len, 1, 0);
		if (*minor) {
			return GSS_S_FAILURE;
		}
	}

	*minor = gss_prepend_mbuf(mbp, mic.value, mic.length);

	return *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

uint32_t
gss_krb5_3des_unwrap_mbuf(uint32_t *minor,
    gss_ctx_id_t ctx,
    mbuf_t *mbp,
    size_t len,
    int *conf_state,
    gss_qop_t *qop)
{
	crypto_ctx_t cctx = &ctx->gss_cryptor;
	const struct ccmode_cbc *ccmode = cctx->dec_mode;
	size_t length = 0, offset;
	gss_buffer_desc hash;
	uint8_t hashval[cctx->digest_size];
	gss_buffer_desc itoken;
	uint8_t tbuffer[GSS_KRB5_3DES_MAXTOKSZ + cctx->digest_size];
	itoken.length = GSS_KRB5_3DES_MAXTOKSZ + cctx->digest_size;
	itoken.value = tbuffer;
	gss_1964_wrap_token_desc wrap = wrap_1964_token;
	gss_buffer_desc header;
	uint8_t padlen;
	mbuf_t smb, tmb;
	int cflag, verified, reverse = 0;

	if (len < GSS_KRB5_3DES_MAXTOKSZ) {
		*minor = EBADRPC;
		return GSS_S_FAILURE;
	}

	if (*qop == GSS_C_QOP_REVERSE) {
		reverse = 1;
	}
	*qop = GSS_C_QOP_DEFAULT;

	*minor = mbuf_copydata(*mbp, 0, itoken.length, itoken.value);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	hash.length = cctx->digest_size;
	hash.value = hashval;
	wrap.Sign_Alg[0] = 0x04;
	wrap.Sign_Alg[1] = 0x00;
	wrap.Seal_Alg[0] = 0x02;
	wrap.Seal_Alg[1] = 0x00;

	for (cflag = 1; cflag >= 0; cflag--) {
		*minor = gss_krb5_3des_token_get(ctx, &itoken, wrap, &hash, &offset, &length, reverse);
		if (*minor == 0) {
			break;
		}
		wrap.Seal_Alg[0] = 0xff;
		wrap.Seal_Alg[0] = 0xff;
	}
	if (*minor) {
		return GSS_S_FAILURE;
	}

	if (conf_state) {
		*conf_state = cflag;
	}

	/*
	 * Seperate off the header
	 */
	*minor = gss_normalize_mbuf(*mbp, offset, &length, &smb, &tmb, 0);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	assert(tmb == NULL);

	/* Decrypt the chain if needed */
	if (cflag) {
		*minor = krb5_crypt_mbuf(cctx, &smb, length, 0, NULL);
		if (*minor) {
			return GSS_S_FAILURE;
		}
	}

	/* Verify the mic */
	header.length = sizeof(gss_1964_wrap_token_desc);
	header.value = &wrap;

	*minor = krb5_mic_mbuf(cctx, &header, smb, 0, length, NULL, hashval, &verified, 0, 0);
	if (!verified) {
		return GSS_S_BAD_SIG;
	}
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Get the pad bytes */
	*minor = mbuf_copydata(smb, length - 1, 1, &padlen);
	if (*minor) {
		return GSS_S_FAILURE;
	}

	/* Strip the confounder and trailing pad bytes */
	gss_strip_mbuf(smb, -padlen);
	gss_strip_mbuf(smb, ccmode->block_size);

	if (*mbp != smb) {
		mbuf_freem(*mbp);
		*mbp = smb;
	}

	return GSS_S_COMPLETE;
}

static const char *
etype_name(etypes etype)
{
	switch (etype) {
	case DES3_CBC_SHA1_KD:
		return "des3-cbc-sha1";
	case AES128_CTS_HMAC_SHA1_96:
		return "aes128-cts-hmac-sha1-96";
	case AES256_CTS_HMAC_SHA1_96:
		return "aes-cts-hmac-sha1-96";
	default:
		return "unknown enctype";
	}
}

static int
supported_etype(uint32_t proto, etypes etype)
{
	const char *proto_name;

	switch (proto) {
	case 0:
		/* RFC 1964 */
		proto_name = "RFC 1964 krb5 gss mech";
		switch (etype) {
		case DES3_CBC_SHA1_KD:
			return 1;
		default:
			break;
		}
		break;
	case 1:
		/* RFC 4121 */
		proto_name = "RFC 4121 krb5 gss mech";
		switch (etype) {
		case AES256_CTS_HMAC_SHA1_96:
		case AES128_CTS_HMAC_SHA1_96:
			return 1;
		default:
			break;
		}
		break;
	default:
		proto_name = "Unknown krb5 gss mech";
		break;
	}
	printf("%s: Non supported encryption %s (%d) type for protocol %s (%d)\n",
	    __func__, etype_name(etype), etype, proto_name, proto);
	return 0;
}

/*
 * Kerberos gss mech entry points
 */
uint32_t
gss_krb5_get_mic(uint32_t *minor,       /* minor_status */
    gss_ctx_id_t ctx,                   /* context_handle */
    gss_qop_t qop,                      /* qop_req */
    gss_buffer_t mbp,                   /* message buffer */
    gss_buffer_t mic /* message_token */)
{
	uint32_t minor_stat = 0;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	*minor = 0;

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		return gss_krb5_3des_get_mic(minor, ctx, qop, mbp, mic);
	case 1:
		/* RFC 4121 CFX case */
		return gss_krb5_cfx_get_mic(minor, ctx, qop, mbp, mic);
	}

	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_verify_mic(uint32_t *minor,            /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    gss_buffer_t mbp,                           /* message_buffer */
    gss_buffer_t mic,                           /* message_token */
    gss_qop_t *qop /* qop_state */)
{
	uint32_t minor_stat = 0;
	gss_qop_t qop_val = GSS_C_QOP_DEFAULT;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	if (qop == NULL) {
		qop = &qop_val;
	}

	*minor = 0;

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		return gss_krb5_3des_verify_mic(minor, ctx, mbp, mic, qop);
	case 1:
		/* RFC 4121 CFX case */
		return gss_krb5_cfx_verify_mic(minor, ctx, mbp, mic, qop);
	}
	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_get_mic_mbuf(uint32_t *minor,  /* minor_status */
    gss_ctx_id_t ctx,                   /* context_handle */
    gss_qop_t qop,                      /* qop_req */
    mbuf_t mbp,                         /* message mbuf */
    size_t offset,                      /* offest */
    size_t len,                         /* length */
    gss_buffer_t mic /* message_token */)
{
	uint32_t minor_stat = 0;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	*minor = 0;

	if (len == 0) {
		len = ~(size_t)0;
	}

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		return gss_krb5_3des_get_mic_mbuf(minor, ctx, qop, mbp, offset, len, mic);
	case 1:
		/* RFC 4121 CFX case */
		return gss_krb5_cfx_get_mic_mbuf(minor, ctx, qop, mbp, offset, len, mic);
	}

	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_verify_mic_mbuf(uint32_t *minor,               /* minor_status */
    gss_ctx_id_t ctx,                                   /* context_handle */
    mbuf_t mbp,                                         /* message_buffer */
    size_t offset,                              /* offset */
    size_t len,                                         /* length */
    gss_buffer_t mic,                                   /* message_token */
    gss_qop_t *qop /* qop_state */)
{
	uint32_t minor_stat = 0;
	gss_qop_t qop_val = GSS_C_QOP_DEFAULT;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	if (qop == NULL) {
		qop = &qop_val;
	}

	*minor = 0;

	if (len == 0) {
		len = ~(size_t)0;
	}

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		return gss_krb5_3des_verify_mic_mbuf(minor, ctx, mbp, offset, len, mic, qop);
	case 1:
		/* RFC 4121 CFX case */
		return gss_krb5_cfx_verify_mic_mbuf(minor, ctx, mbp, offset, len, mic, qop);
	}

	return GSS_S_COMPLETE;
}

uint32_t
gss_krb5_wrap_mbuf(uint32_t *minor,     /* minor_status */
    gss_ctx_id_t ctx,                   /* context_handle */
    int conf_flag,                      /* conf_req_flag */
    gss_qop_t qop,                      /* qop_req */
    mbuf_t *mbp,                        /* input/output message_buffer */
    size_t offset,                      /* offset */
    size_t len,                         /* length */
    int *conf_state /* conf state */)
{
	uint32_t major, minor_stat = 0;
	mbuf_t smb, tmb;
	int conf_val = 0;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	if (conf_state == NULL) {
		conf_state = &conf_val;
	}

	*minor = 0;

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	gss_normalize_mbuf(*mbp, offset, &len, &smb, &tmb, 0);

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		major = gss_krb5_3des_wrap_mbuf(minor, ctx, conf_flag, qop, &smb, len, conf_state);
		break;
	case 1:
		/* RFC 4121 CFX case */
		major = gss_krb5_cfx_wrap_mbuf(minor, ctx, conf_flag, qop, &smb, len, conf_state);
		break;
	}

	if (offset) {
		gss_join_mbuf(*mbp, smb, tmb);
	} else {
		*mbp = smb;
		gss_join_mbuf(smb, tmb, NULL);
	}

	return major;
}

uint32_t
gss_krb5_unwrap_mbuf(uint32_t * minor,          /* minor_status */
    gss_ctx_id_t ctx,                           /* context_handle */
    mbuf_t *mbp,                                /* input/output message_buffer */
    size_t offset,                              /* offset */
    size_t len,                                 /* length */
    int *conf_flag,                             /* conf_state */
    gss_qop_t *qop /* qop state */)
{
	uint32_t major, minor_stat = 0;
	gss_qop_t qop_val = GSS_C_QOP_DEFAULT;
	int conf_val = 0;
	mbuf_t smb, tmb;

	if (minor == NULL) {
		minor = &minor_stat;
	}
	if (qop == NULL) {
		qop = &qop_val;
	}
	if (conf_flag == NULL) {
		conf_flag = &conf_val;
	}

	/* Validate context */
	if (ctx == NULL || ((lucid_context_version_t)ctx)->version != 1) {
		return GSS_S_NO_CONTEXT;
	}

	if (!supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_cryptor.etype)) {
		*minor = ENOTSUP;
		return GSS_S_FAILURE;
	}

	gss_normalize_mbuf(*mbp, offset, &len, &smb, &tmb, 0);

	switch (ctx->gss_lucid_ctx.key_data.proto) {
	case 0:
		/* RFC 1964 DES3 case */
		major = gss_krb5_3des_unwrap_mbuf(minor, ctx, &smb, len, conf_flag, qop);
		break;
	case 1:
		/* RFC 4121 CFX case */
		major = gss_krb5_cfx_unwrap_mbuf(minor, ctx, &smb, len, conf_flag, qop);
		break;
	}

	if (offset) {
		gss_join_mbuf(*mbp, smb, tmb);
	} else {
		*mbp = smb;
		gss_join_mbuf(smb, tmb, NULL);
	}

	return major;
}

#include <nfs/xdr_subs.h>

static int
xdr_lucid_context(void *data, size_t length, lucid_context_t lctx)
{
	struct xdrbuf xb;
	int error = 0;
	uint32_t keylen = 0;

	xb_init_buffer(&xb, data, length);
	xb_get_32(error, &xb, lctx->vers);
	if (!error && lctx->vers != 1) {
		error = EINVAL;
		printf("%s: invalid version %d\n", __func__, (int)lctx->vers);
		goto out;
	}
	xb_get_32(error, &xb, lctx->initiate);
	if (error) {
		printf("%s: Could not decode initiate\n", __func__);
		goto out;
	}
	xb_get_32(error, &xb, lctx->endtime);
	if (error) {
		printf("%s: Could not decode endtime\n", __func__);
		goto out;
	}
	xb_get_64(error, &xb, lctx->send_seq);
	if (error) {
		printf("%s: Could not decode send_seq\n", __func__);
		goto out;
	}
	xb_get_64(error, &xb, lctx->recv_seq);
	if (error) {
		printf("%s: Could not decode recv_seq\n", __func__);
		goto out;
	}
	xb_get_32(error, &xb, lctx->key_data.proto);
	if (error) {
		printf("%s: Could not decode mech protocol\n", __func__);
		goto out;
	}
	switch (lctx->key_data.proto) {
	case 0:
		xb_get_32(error, &xb, lctx->key_data.lucid_protocol_u.data_1964.sign_alg);
		xb_get_32(error, &xb, lctx->key_data.lucid_protocol_u.data_1964.seal_alg);
		if (error) {
			printf("%s: Could not decode rfc1964 sign and seal\n", __func__);
		}
		break;
	case 1:
		xb_get_32(error, &xb, lctx->key_data.lucid_protocol_u.data_4121.acceptor_subkey);
		if (error) {
			printf("%s: Could not decode rfc4121 acceptor_subkey", __func__);
		}
		break;
	default:
		printf("%s: Invalid mech protocol %d\n", __func__, (int)lctx->key_data.proto);
		error = EINVAL;
	}
	if (error) {
		goto out;
	}
	xb_get_32(error, &xb, lctx->ctx_key.etype);
	if (error) {
		printf("%s: Could not decode key enctype\n", __func__);
		goto out;
	}
	switch (lctx->ctx_key.etype) {
	case DES3_CBC_SHA1_KD:
		keylen = 24;
		break;
	case AES128_CTS_HMAC_SHA1_96:
		keylen = 16;
		break;
	case AES256_CTS_HMAC_SHA1_96:
		keylen = 32;
		break;
	default:
		error = ENOTSUP;
		goto out;
	}
	xb_get_32(error, &xb, lctx->ctx_key.key.key_len);
	if (error) {
		printf("%s: could not decode key length\n", __func__);
		goto out;
	}
	if (lctx->ctx_key.key.key_len != keylen) {
		error = EINVAL;
		printf("%s: etype = %d keylen = %d expected keylen = %d\n", __func__,
		    lctx->ctx_key.etype, lctx->ctx_key.key.key_len, keylen);
		goto out;
	}

	lctx->ctx_key.key.key_val = xb_malloc(keylen);
	if (lctx->ctx_key.key.key_val == NULL) {
		printf("%s: could not get memory for key\n", __func__);
		error = ENOMEM;
		goto out;
	}
	error = xb_get_bytes(&xb, (char *)lctx->ctx_key.key.key_val, keylen, 1);
	if (error) {
		printf("%s: could get key value\n", __func__);
		xb_free(lctx->ctx_key.key.key_val);
	}
out:
	return error;
}

gss_ctx_id_t
gss_krb5_make_context(void *data, uint32_t datalen)
{
	gss_ctx_id_t ctx;

	if (!corecrypto_available()) {
		return NULL;
	}

	gss_krb5_mech_init();
	MALLOC(ctx, gss_ctx_id_t, sizeof(struct gss_ctx_id_desc), M_TEMP, M_WAITOK | M_ZERO);
	if (xdr_lucid_context(data, datalen, &ctx->gss_lucid_ctx) ||
	    !supported_etype(ctx->gss_lucid_ctx.key_data.proto, ctx->gss_lucid_ctx.ctx_key.etype)) {
		FREE(ctx, M_TEMP);
		FREE(data, M_TEMP);
		return NULL;
	}

	/* Set up crypto context */
	gss_crypto_ctx_init(&ctx->gss_cryptor, &ctx->gss_lucid_ctx);
	FREE(data, M_TEMP);

	return ctx;
}

void
gss_krb5_destroy_context(gss_ctx_id_t ctx)
{
	if (ctx == NULL) {
		return;
	}
	gss_crypto_ctx_free(&ctx->gss_cryptor);
	FREE(ctx->gss_lucid_ctx.ctx_key.key.key_val, M_TEMP);
	cc_clear(sizeof(lucid_context_t), &ctx->gss_lucid_ctx);
	FREE(ctx, M_TEMP);
}
