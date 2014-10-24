/*
 *  ccdigest_priv.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 12/7/10.
 *  Copyright 2010,2011 Apple, Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCDIGEST_PRIV_H_
#define _CORECRYPTO_CCDIGEST_PRIV_H_

#include <corecrypto/ccdigest.h>

void ccdigest_final_common(const struct ccdigest_info *di,
                           ccdigest_ctx_t ctx, void *digest);
void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t,
                         unsigned char *digest);
void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t,
                         unsigned char *digest);

#endif /* _CORECRYPTO_CCDIGEST_PRIV_H_ */
