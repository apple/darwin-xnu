/*
 * Copyright (c) 2007-2010 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*!
 @header corecrypto/ccdrbg.h
 @abstract The functions provided in ccdrbg.h implement high-level accessors
 to cryptographically secure random numbers.

 */

#ifndef _CORECRYPTO_CCDRBG_H_
#define _CORECRYPTO_CCDRBG_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg_impl.h>

/* TODO: Error codes ? */
#define CCDRBG_STATUS_OK 0
#define CCDRBG_STATUS_ERROR (-1)
#define CCDRBG_STATUS_NEED_RESEED (-2)
#define CCDRBG_STATUS_PARAM_ERROR (-3)

CC_INLINE size_t ccdrbg_context_size(const struct ccdrbg_info *drbg)
{
    return drbg->size;
}

CC_INLINE int ccdrbg_init(const struct ccdrbg_info *info,
			struct ccdrbg_state *drbg,
            unsigned long entropyLength, const void* entropy,
            unsigned long nonceLength, const void* nonce,
            unsigned long psLength, const void* ps)
{
	return info->init(info, drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);
}

CC_INLINE int ccdrbg_reseed(const struct ccdrbg_info *info,
		struct ccdrbg_state *prng,
		unsigned long entropylen, const void *entropy,
		unsigned long inlen, const void *in)
{
	return info->reseed(prng, entropylen, entropy, inlen, in);
}


CC_INLINE int ccdrbg_generate(const struct ccdrbg_info *info,
		struct ccdrbg_state *prng,
		unsigned long outlen, void *out,
		unsigned long inlen, const void *in)
{
	return info->generate(prng, outlen, out, inlen, in);
}

CC_INLINE void ccdrbg_done(const struct ccdrbg_info *info,
		struct ccdrbg_state *prng)
{
	info->done(prng);
}


extern struct ccdrbg_info ccdrbg_dummy_info;
extern struct ccdrbg_info ccdrbg_fipssha1_info;

struct ccdrbg_nistctr_custom {
    const struct ccmode_ecb *ecb;
    unsigned long keylen;
    int strictFIPS;
    int use_df;
};

void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom);

extern struct ccdrbg_info ccdrbg_nistdigest_info;

struct ccdrbg_nisthmac_custom {
    const struct ccdigest_info *di;
    int strictFIPS;
};

// "class" method on nisthmac dbrg's to ask about their security_strength for a given di
int ccdbrg_nisthmac_security_strength(const struct ccdrbg_nisthmac_custom *custom);

void ccdrbg_factory_nisthmac(struct ccdrbg_info *info, const struct ccdrbg_nisthmac_custom *custom);

#endif /* _CORECRYPTO_CCDRBG_H_ */
