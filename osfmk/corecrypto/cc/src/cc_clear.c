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

//rdar://problem/26986552

#if ( CC_HAS_MEMSET_S == 1 ) && (defined( __STDC_WANT_LIB_EXT1__ ) && ( __STDC_WANT_LIB_EXT1__ == 1 ) )
void cc_clear(size_t len, void *dst)
{
    memset_s(dst,len,0,len);
}
#elif defined(_WIN32) && !defined(__clang__) //Clang with Microsoft CodeGen, doesn't support SecureZeroMemory
#include <windows.h>
static void cc_clear(size_t len, void *dst)
{
    SecureZeroMemory(dst, len);
}
#else
void cc_clear(size_t len, void *dst)
{
    volatile char *vptr = (volatile char *)dst;
    while (len--)
        *vptr++ = '\0';
}
#endif

/* This is an altarnative for clang that should work
 void cc_clear(size_t len, void *dst) __attribute__ ((optnone))
 {
 cc_zero(len,dst);
 }
*/
