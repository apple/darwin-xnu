//
//  ccn_set.c
//  corecrypto
//
//  Created by Fabrice Gautier on 2/17/12.
//  Copyright (c) 2012 Apple, Inc. All rights reserved.
//

#include <corecrypto/ccn.h>

#if !CCN_SET_ASM
void ccn_set(cc_size n, cc_unit *r, const cc_unit *s)
{
    CC_MEMCPY(r, s, ccn_sizeof_n(n));
}
#endif
