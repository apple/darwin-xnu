/*
 *  ccmd5.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 12/3/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCMD5_H_
#define _CORECRYPTO_CCMD5_H_

#include <corecrypto/ccdigest.h>

#define CCMD5_BLOCK_SIZE   64
#define CCMD5_OUTPUT_SIZE  16
#define CCMD5_STATE_SIZE   16

extern const uint32_t ccmd5_initial_state[4];

/* Selector */
const struct ccdigest_info *ccmd5_di(void);

/* Implementations */
extern const struct ccdigest_info ccmd5_ltc_di;

#endif /* _CORECRYPTO_CCMD5_H_ */
