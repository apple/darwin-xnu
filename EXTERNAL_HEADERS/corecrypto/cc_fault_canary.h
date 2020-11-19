/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef corecrypto_cc_fault_canary_h
#define corecrypto_cc_fault_canary_h

#include "cc.h"

#define CC_FAULT_CANARY_SIZE 16
typedef uint8_t cc_fault_canary_t[CC_FAULT_CANARY_SIZE];

extern const cc_fault_canary_t CCEC_FAULT_CANARY;
extern const cc_fault_canary_t CCRSA_PKCS1_FAULT_CANARY;
extern const cc_fault_canary_t CCRSA_PSS_FAULT_CANARY;

#define CC_FAULT_CANARY_MEMCPY(_dst_, _src_) memcpy(_dst_, _src_, CC_FAULT_CANARY_SIZE)
#define CC_FAULT_CANARY_CLEAR(_name_) memset(_name_, 0x00, CC_FAULT_CANARY_SIZE)

#define CC_FAULT_CANARY_EQUAL(_a_, _b_) (cc_cmp_safe(CC_FAULT_CANARY_SIZE, _a_, _b_) == 0)

#endif /* corecrypto_cc_fault_canary_h */
