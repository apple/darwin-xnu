/*
 *  cc.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/16/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CC_H_
#define _CORECRYPTO_CC_H_

#include <corecrypto/cc_config.h>
#include <string.h>
#include <stdint.h>

#if CC_KERNEL
#include <kern/assert.h>
#else
#include <assert.h>
#include <stdio.h>
#endif

/* Declare a struct element with a guarenteed alignment of _alignment_.
   The resulting struct can be used to create arrays that are aligned by
   a certain amount.  */
#define cc_aligned_struct(_alignment_)  \
    typedef struct { \
        uint8_t b[_alignment_]; \
    } __attribute__((aligned(_alignment_)))

/* number of array elements used in a cc_ctx_decl */
#define cc_ctx_n(_type_, _size_) ((_size_ + sizeof(_type_) - 1) / sizeof(_type_))

/* sizeof of a context declared with cc_ctx_decl */
#define cc_ctx_sizeof(_type_, _size_) sizeof(_type_[cc_ctx_n(_type_, _size_)])

#define cc_ctx_decl(_type_, _size_, _name_)  \
    _type_ _name_[cc_ctx_n(_type_, _size_)]

#if CC_HAS_BZERO
#define cc_zero(_size_,_data_) bzero((_data_), (_size_))
#else
/* Alternate version if you don't have bzero. */
#define cc_zero(_size_,_data_) memset((_data_),0 ,(_size_))
#endif

#if CC_KERNEL
#define cc_printf(x...) printf(x)
#else
#define cc_printf(x...) fprintf(stderr, x)
#endif

#define cc_assert(x) assert(x)

#define cc_copy(_size_, _dst_, _src_) memcpy(_dst_, _src_, _size_)

CC_INLINE CC_NONNULL2 CC_NONNULL3 CC_NONNULL4
void cc_xor(size_t size, void *r, const void *s, const void *t) {
    uint8_t *_r=(uint8_t *)r;
    const uint8_t *_s=(uint8_t *)s;
    const uint8_t *_t=(uint8_t *)t;
    while (size--) {
        _r[size] = _s[size] ^ _t[size];
    }
}

/* Exchange S and T of any type.  NOTE: Both and S and T are evaluated
   mutliple times and MUST NOT be expressions. */
#define CC_SWAP(S,T)  do { \
    __typeof__(S) _cc_swap_tmp = S; S = T; T = _cc_swap_tmp; \
} while(0)

/* Return the maximum value between S and T. */
#define CC_MAX(S, T) ({__typeof__(S) _cc_max_s = S; __typeof__(T) _cc_max_t = T; _cc_max_s > _cc_max_t ? _cc_max_s : _cc_max_t;})

/* Return the minimum value between S and T. */
#define CC_MIN(S, T) ({__typeof__(S) _cc_min_s = S; __typeof__(T) _cc_min_t = T; _cc_min_s <= _cc_min_t ? _cc_min_s : _cc_min_t;})

#endif /* _CORECRYPTO_CC_H_ */
