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

#ifndef _CORECRYPTO_CCSHA2_H_
#define _CORECRYPTO_CCSHA2_H_

#include <corecrypto/ccdigest.h>

/* sha2 selectors */
const struct ccdigest_info *ccsha224_di(void);
const struct ccdigest_info *ccsha256_di(void);
const struct ccdigest_info *ccsha384_di(void);
const struct ccdigest_info *ccsha512_di(void);
const struct ccdigest_info *ccsha512_256_di(void);  // SHA512/256 (cf FIPS 180-4 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

#define ccoid_sha224 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04")
#define ccoid_sha224_len 11

#define ccoid_sha256 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")
#define ccoid_sha256_len 11

#define ccoid_sha384 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02")
#define ccoid_sha384_len 11

#define ccoid_sha512 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")
#define ccoid_sha512_len 11

#define ccoid_sha512_256 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06")
#define ccoid_sha512_256_len 11

/* SHA256 */
#define CCSHA256_BLOCK_SIZE  64
#define	CCSHA256_OUTPUT_SIZE 32
#define	CCSHA256_STATE_SIZE  32
extern const struct ccdigest_info ccsha256_ltc_di;
#if  CCSHA2_VNG_INTEL
extern const struct ccdigest_info ccsha224_vng_intel_SupplementalSSE3_di;
extern const struct ccdigest_info ccsha256_vng_intel_SupplementalSSE3_di;
#endif
#if  CCSHA2_VNG_ARM
extern const struct ccdigest_info ccsha224_vng_arm_di;
extern const struct ccdigest_info ccsha256_vng_arm_di;
#if CC_ACCELERATECRYPTO && defined(__arm64__) && CCSHA2_VNG_ARM
extern const struct ccdigest_info ccsha256_vng_arm64neon_di;
#endif  // CC_ACCELERATECRYPTO
extern const struct ccdigest_info ccsha384_vng_arm_di;
extern const struct ccdigest_info ccsha512_vng_arm_di;
extern const struct ccdigest_info ccsha512_256_vng_arm_di;
#endif

/* SHA224 */
#define	CCSHA224_OUTPUT_SIZE 28
extern const struct ccdigest_info ccsha224_ltc_di;

/* SHA512 */
#define CCSHA512_BLOCK_SIZE  128
#define	CCSHA512_OUTPUT_SIZE  64
#define	CCSHA512_STATE_SIZE   64
extern const struct ccdigest_info ccsha512_ltc_di;

/* SHA512/256 */
// FIPS 180-4
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
#define CCSHA512_256_BLOCK_SIZE  128
#define CCSHA512_256_OUTPUT_SIZE  32
#define CCSHA512_256_STATE_SIZE   64
extern const struct ccdigest_info ccsha512_256_ltc_di;

/* SHA384 */
#define	CCSHA384_OUTPUT_SIZE  48
extern const struct ccdigest_info ccsha384_ltc_di;

#endif /* _CORECRYPTO_CCSHA2_H_ */
