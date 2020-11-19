/* Copyright (c) (2010,2011,2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDIGEST_PRIV_H_
#define _CORECRYPTO_CCDIGEST_PRIV_H_

#include <corecrypto/cc_priv.h>
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

#define ccdigest_copy_state(_di_, _dst_, _src_) cc_memcpy_nochk(_dst_, _src_, (_di_)->state_size)

#endif /* _CORECRYPTO_CCDIGEST_PRIV_H_ */
