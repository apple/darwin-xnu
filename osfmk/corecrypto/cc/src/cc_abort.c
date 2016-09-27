/*
 *  cc_abort.c
 *  corecrypto
 *
 *  Created on 7/16/2015
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cc_priv.h>

//cc_abort() is implemented to comply with by FIPS 140-2, when DRBG produces
//two equal consecutive blocks. See radar 19129408

#if CC_KERNEL
#include <kern/debug.h>
void cc_abort(const char * msg CC_UNUSED , ...)
{
    panic(msg);
}

#elif CC_USE_SEPROM || CC_USE_S3 || CC_BASEBAND || CC_EFI || CC_IBOOT
void cc_abort(const char * msg CC_UNUSED, ...)
{
    //do nothing and return becasue we don't have panic() in those
    //environments
}

#else
#include <stdlib.h>
void cc_abort(const char * msg CC_UNUSED, ...)
{
    abort();
}
#endif
