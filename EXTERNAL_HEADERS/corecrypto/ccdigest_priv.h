/*
 *  ccdigest_priv.h
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2011,2012,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCDIGEST_PRIV_H_
#define _CORECRYPTO_CCDIGEST_PRIV_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccasn1.h>

CC_INLINE CC_NONNULL((1))
bool ccdigest_oid_equal(const struct ccdigest_info *di, ccoid_t oid) {
    if(di->oid == NULL && CCOID(oid) == NULL) return true;
    if(di->oid == NULL || CCOID(oid) == NULL) return false;
    return ccoid_equal(di->oid, oid);
}

typedef const struct ccdigest_info *(ccdigest_lookup)(ccoid_t oid);

#include <stdarg.h>
const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...);

#endif /* _CORECRYPTO_CCDIGEST_PRIV_H_ */
