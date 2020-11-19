/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSHA1_H_
#define _CORECRYPTO_CCSHA1_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_config.h>

#define CCSHA1_BLOCK_SIZE   64
#define CCSHA1_OUTPUT_SIZE  20
#define CCSHA1_STATE_SIZE   20

/* sha1 selector */
const struct ccdigest_info *ccsha1_di(void);

/* Implementations */
extern const struct ccdigest_info ccsha1_ltc_di;
extern const struct ccdigest_info ccsha1_eay_di;

#if  CCSHA1_VNG_INTEL
extern const struct ccdigest_info ccsha1_vng_intel_SupplementalSSE3_di;
#endif

#if  CCSHA1_VNG_ARM
extern const struct ccdigest_info ccsha1_vng_arm_di;
#endif

#define ccoid_sha1 ((unsigned char *)"\x06\x05\x2b\x0e\x03\x02\x1a")
#define ccoid_sha1_len 7

#endif /* _CORECRYPTO_CCSHA1_H_ */
