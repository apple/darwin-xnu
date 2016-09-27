/*
 *  cc_cmp_safe.c
 *  corecrypto
 *
 *  Created on 04/22/2014
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cc_priv.h>

int cc_cmp_safe (size_t num, const void * ptr1, const void * ptr2)
{
    size_t i;
    const uint8_t *s=(const uint8_t *)ptr1;
    const uint8_t *t=(const uint8_t *)ptr2;
    uint8_t flag=((num<=0)?1:0); // If 0 return an error
    for (i=0;i<num;i++)
    {
        flag|=(s[i]^t[i]);
    }
    HEAVISIDE_STEP_UINT8(flag,flag); // flag=(flag==0)?0:1;
    return flag; // 0 iff all bytes were equal, 1 if there is any difference
}
