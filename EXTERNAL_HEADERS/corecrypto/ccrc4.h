/*
 *  ccrc4.h
 *  corecrypto
 *
 *  Created by Fabrice Gautier on 12/22/10.
 *  Copyright 2010,2011 Apple, Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCRC4_H_
#define _CORECRYPTO_CCRC4_H_

#include <corecrypto/ccmode.h>

cc_aligned_struct(16) ccrc4_ctx;

/* Declare a gcm key named _name_.  Pass the size field of a struct ccmode_gcm
 for _size_. */
#define ccrc4_ctx_decl(_size_, _name_) cc_ctx_decl(ccrc4_ctx, _size_, _name_)
#define ccrc4_ctx_clear(_size_, _name_) cc_ctx_clear(ccrc4_ctx, _size_, _name_)

struct ccrc4_info {
    size_t size;        /* first argument to ccrc4_ctx_decl(). */
    void (*init)(ccrc4_ctx *ctx, unsigned long key_len, const void *key);
    void (*crypt)(ccrc4_ctx *ctx, unsigned long nbytes, const void *in, void *out);
};


const struct ccrc4_info *ccrc4(void);

extern const struct ccrc4_info ccrc4_eay;

struct ccrc4_vector {
    unsigned long keylen;
    const void *key;
    unsigned long datalen;
    const void *pt;
    const void *ct;
};

int ccrc4_test(const struct ccrc4_info *rc4, const struct ccrc4_vector *v);

#endif /* _CORECRYPTO_CCRC4_H_ */
