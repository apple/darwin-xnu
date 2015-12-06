/*
 *  ccn_set.c
 *  corecrypto
 *
 *  Created on 02/17/2012
 *
 *  Copyright (c) 2012,2014,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

#if !CCN_SET_ASM
void ccn_set(cc_size n, cc_unit *r, const cc_unit *s)
{
    CC_MEMMOVE(r, s, ccn_sizeof_n(n));
}
#endif
