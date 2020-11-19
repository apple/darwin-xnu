/*
 *  ccdrbg_nisthmac.c
 *  corecrypto
 *
 *  Created on 05/09/2014
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
 *
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

#include <stdbool.h>

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_macros.h>

// This HMAC DRBG is described in:

// NIST SP 800-90A Rev. 1
// Recommendation for Random Number Generation Using Deterministic Random Bit Generators
// June 2015

// See in particular:
// - 9 DRBG Mechanism Functions
// - 10.1.2 HMAC_DRBG
// - B.2 HMAC_DRBGExample

#define NISTHMAC_MAX_OUTPUT_SIZE (CCSHA512_OUTPUT_SIZE)

#define MIN_REQ_ENTROPY(di) ((di)->output_size / 2)

struct ccdrbg_nisthmac_state {
	const struct ccdrbg_nisthmac_custom *custom;
	uint8_t key[NISTHMAC_MAX_OUTPUT_SIZE];
	uint8_t V[NISTHMAC_MAX_OUTPUT_SIZE];
	uint64_t reseed_counter;
};

#define DRBG_NISTHMAC_DEBUG 0

#if DRBG_NISTHMAC_DEBUG
#include <corecrypto/cc_debug.h>

static void
dump_state(const char *label, struct ccdrbg_nisthmac_state *drbg_ctx)
{
	size_t outlen = drbg_ctx->custom->di->output_size;

	cc_print(label, outlen, drbg_ctx->key);
	cc_print(label, outlen, drbg_ctx->V);
}
#endif

// See NIST SP 800-90A, Rev. 1, 9.4
static void
done(struct ccdrbg_state *ctx)
{
	cc_clear(sizeof(struct ccdrbg_nisthmac_state), ctx);
}

// See NIST SP 800-90A, Rev. 1, 10.1.2.2
static void
update(struct ccdrbg_state *ctx, unsigned ndata, ...)
{
	struct ccdrbg_nisthmac_state *drbg_ctx = (struct ccdrbg_nisthmac_state *)ctx;
	const struct ccdigest_info *info = drbg_ctx->custom->di;
	size_t outlen = info->output_size;
	size_t data_nbytes = 0;
	va_list args;

	cchmac_di_decl(info, hmac_ctx);

	for (uint8_t b = 0; b < 2; b += 1) {
		cchmac_init(info, hmac_ctx, outlen, drbg_ctx->key);

		cchmac_update(info, hmac_ctx, outlen, drbg_ctx->V);

		cchmac_update(info, hmac_ctx, sizeof(b), &b);

		va_start(args, ndata);

		for (unsigned i = 0; i < ndata; i += 1) {
			size_t nbytes = va_arg(args, size_t);
			const void *buf = va_arg(args, const void *);

			cchmac_update(info, hmac_ctx, nbytes, buf);

			data_nbytes += nbytes;
		}

		va_end(args);

		cchmac_final(info, hmac_ctx, drbg_ctx->key);

		cchmac(info, outlen, drbg_ctx->key, outlen, drbg_ctx->V, drbg_ctx->V);

		if (data_nbytes == 0) {
			break;
		}
	}

	cchmac_di_clear(info, hmac_ctx);
}

static bool
entropy_isvalid(size_t entropy_nbytes, const struct ccdigest_info *info)
{
	return (entropy_nbytes <= CCDRBG_MAX_ENTROPY_SIZE) && (entropy_nbytes >= MIN_REQ_ENTROPY(info));
}

// See NIST SP 800-90A, Rev. 1, 9.1 and 10.1.2.3
static int
init(const struct ccdrbg_info *info,
    struct ccdrbg_state *ctx,
    size_t entropy_nbytes,
    const void *entropy,
    size_t nonce_nbytes,
    const void *nonce,
    size_t ps_nbytes,
    const void *ps)
{
	struct ccdrbg_nisthmac_state *drbg_ctx = (struct ccdrbg_nisthmac_state *)ctx;
	drbg_ctx->custom = info->custom;
	const struct ccdigest_info *digest_info = drbg_ctx->custom->di;
	size_t outlen = digest_info->output_size;

	int status = CCDRBG_STATUS_PARAM_ERROR;
	cc_require(outlen <= NISTHMAC_MAX_OUTPUT_SIZE, out);
	cc_require(entropy_isvalid(entropy_nbytes, digest_info), out);
	cc_require(ps_nbytes <= CCDRBG_MAX_PSINPUT_SIZE, out);

	status = CCDRBG_STATUS_OK;

	cc_memset(drbg_ctx->key, 0, outlen);
	cc_memset(drbg_ctx->V, 1, outlen);

	update(ctx, 3, entropy_nbytes, entropy, nonce_nbytes, nonce, ps_nbytes, ps);

	drbg_ctx->reseed_counter = 1;

out:
	return status;
}

static bool
add_isvalid(size_t add_nbytes)
{
	return add_nbytes <= CCDRBG_MAX_ADDITIONALINPUT_SIZE;
}

// See NIST SP 800-90A, Rev. 1, 9.2 and 10.1.2.4
static int
reseed(struct ccdrbg_state *ctx, size_t entropy_nbytes, const void *entropy, size_t add_nbytes, const void *add)
{
	struct ccdrbg_nisthmac_state *drbg_ctx = (struct ccdrbg_nisthmac_state *)ctx;
	const struct ccdigest_info *digest_info = drbg_ctx->custom->di;

	int status = CCDRBG_STATUS_PARAM_ERROR;
	cc_require(entropy_isvalid(entropy_nbytes, digest_info), out);
	cc_require(add_isvalid(add_nbytes), out);

	status = CCDRBG_STATUS_OK;

	update(ctx, 2, entropy_nbytes, entropy, add_nbytes, add);

	drbg_ctx->reseed_counter = 1;

out:
	return status;
}

// See NIST SP 800-90A, Rev. 1, 9.3 and 10.1.2.5
static int
generate(struct ccdrbg_state *ctx, size_t out_nbytes, void *out, size_t add_nbytes, const void *add)
{
	struct ccdrbg_nisthmac_state *drbg_ctx = (struct ccdrbg_nisthmac_state *)ctx;
	const struct ccdigest_info *info = drbg_ctx->custom->di;
	size_t outlen = info->output_size;

	int status = CCDRBG_STATUS_PARAM_ERROR;
	cc_require(out_nbytes <= CCDRBG_MAX_REQUEST_SIZE, out);
	cc_require(add_isvalid(add_nbytes), out);

	status = CCDRBG_STATUS_NEED_RESEED;
	cc_require(drbg_ctx->reseed_counter <= CCDRBG_RESEED_INTERVAL || !drbg_ctx->custom->strictFIPS, out);

	status = CCDRBG_STATUS_OK;

	if (add_nbytes > 0) {
		update(ctx, 1, add_nbytes, add);
	}

	uint8_t *out_bytes = out;
	uint8_t Vprev[NISTHMAC_MAX_OUTPUT_SIZE];

	while (out_nbytes > 0) {
		cc_memcpy(Vprev, drbg_ctx->V, outlen);
		cchmac(info, outlen, drbg_ctx->key, outlen, drbg_ctx->V, drbg_ctx->V);

		// See FIPS 140-2, 4.9.2 Conditional Tests
		if (cc_cmp_safe(outlen, Vprev, drbg_ctx->V) == 0) {
			done(ctx);
			status = CCDRBG_STATUS_ABORT;
			cc_try_abort(NULL);
			goto out;
		}

		size_t n = CC_MIN(out_nbytes, outlen);
		cc_memcpy(out_bytes, drbg_ctx->V, n);

		out_bytes += n;
		out_nbytes -= n;
	}

	update(ctx, 1, add_nbytes, add);

	drbg_ctx->reseed_counter += 1;

out:
	cc_clear(outlen, Vprev);
	return status;
}

void
ccdrbg_factory_nisthmac(struct ccdrbg_info *info, const struct ccdrbg_nisthmac_custom *custom)
{
	info->size = sizeof(struct ccdrbg_nisthmac_state) + sizeof(struct ccdrbg_nisthmac_custom);
	info->init = init;
	info->generate = generate;
	info->reseed = reseed;
	info->done = done;
	info->custom = custom;
};
