/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
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

#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/sha2.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include <corecrypto/ccdigest.h>

#if defined(CRYPTO_SHA2)

void SHA256_Init(SHA256_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha256_di;

        /* Make sure the context size for the digest info fits in the one we have */
        if(ccdigest_di_size(di)>sizeof(SHA256_CTX))
                panic("%s: inconsistent size for SHA256 context", __FUNCTION__);
 
	g_crypto_funcs->ccdigest_init_fn(di, ctx->ctx);
}

void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha256_di;

	g_crypto_funcs->ccdigest_update_fn(di, ctx->ctx, len, data);
}

void SHA256_Final(void *digest, SHA256_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha256_di;

	ccdigest_final(di, ctx->ctx, digest);
}

void SHA384_Init(SHA384_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha384_di;

        /* Make sure the context size for the digest info fits in the one we have */
        if(ccdigest_di_size(di)>sizeof(SHA384_CTX))
                panic("%s: inconsistent size for SHA384 context", __FUNCTION__);
 
	g_crypto_funcs->ccdigest_init_fn(di, ctx->ctx);
}

void SHA384_Update(SHA384_CTX *ctx, const void *data, size_t len)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha384_di;

	g_crypto_funcs->ccdigest_update_fn(di, ctx->ctx, len, data);
}


void SHA384_Final(void *digest, SHA384_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha384_di;

	ccdigest_final(di, ctx->ctx, digest);
}

void SHA512_Init(SHA512_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha512_di;

        /* Make sure the context size for the digest info fits in the one we have */
        if(ccdigest_di_size(di)>sizeof(SHA512_CTX))
                panic("%s: inconsistent size for SHA512 context", __FUNCTION__);
 
	g_crypto_funcs->ccdigest_init_fn(di, ctx->ctx);
}

void SHA512_Update(SHA512_CTX *ctx, const void *data, size_t len)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha512_di;

	g_crypto_funcs->ccdigest_update_fn(di, ctx->ctx, len, data);
}

void SHA512_Final(void *digest, SHA512_CTX *ctx)
{
	const struct ccdigest_info *di;
	di=g_crypto_funcs->ccsha512_di;

	ccdigest_final(di, ctx->ctx, digest);
}

#else

/* As these are part of the KPI, we need to stub them out for any kernel configuration that does not support SHA2. */

void UNSUPPORTED_API(SHA256_Init,   SHA256_CTX *ctx);
void UNSUPPORTED_API(SHA384_Init,   SHA384_CTX *ctx);
void UNSUPPORTED_API(SHA512_Init,   SHA512_CTX *ctx);
void UNSUPPORTED_API(SHA256_Update, SHA256_CTX *ctx, const void *data, size_t len);
void UNSUPPORTED_API(SHA384_Update, SHA384_CTX *ctx, const void *data, size_t len);
void UNSUPPORTED_API(SHA512_Update, SHA512_CTX *ctx, const void *data, size_t len);
void UNSUPPORTED_API(SHA256_Final,  void *digest, SHA256_CTX *ctx);
void UNSUPPORTED_API(SHA384_Final,  void *digest, SHA384_CTX *ctx);
void UNSUPPORTED_API(SHA512_Final,  void *digest, SHA512_CTX *ctx);

#endif

