/*
 *  cc_clear.c
 *  corecrypto
 *
 *  Created on 05/21/2014
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cc.h>

void cc_clear(size_t len, void *dst)
{
#if ( CC_HAS_MEMSET_S == 1 ) && (defined( __STDC_WANT_LIB_EXT1__ ) && ( __STDC_WANT_LIB_EXT1__ == 1 ) )
    memset_s(dst,len,0,len);
#else
    volatile size_t ctr=0;
    volatile uint8_t *data=dst;
    if (len) {
        cc_zero(len,dst);
        (void)data[ctr]; // Touch the buffer so that the compiler does not
            // Optimize out the zeroing
    }
#endif
}

