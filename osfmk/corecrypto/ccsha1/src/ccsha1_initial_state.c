/*
 *  ccsha1_initial_state.c
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccsha1.h>
#include <corecrypto/cc_priv.h>

const uint32_t ccsha1_initial_state[5] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
};
