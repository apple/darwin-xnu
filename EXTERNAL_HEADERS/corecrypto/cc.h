/*
 *  cc.h
 *  corecrypto
 *
 *  Created on 12/16/2010
 *
 *  Copyright (c) 2010,2011,2012,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CC_H_
#define _CORECRYPTO_CC_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_error.h>
#include <string.h>
#include <stdint.h>

/* Provide a general purpose macro concat method. */
#define cc_concat_(a, b) a##b
#define cc_concat(a, b) cc_concat_(a, b)

/* Manage asserts here because a few functions in header public files do use asserts */
#define cc_assert(x) assert(x)
#if CC_KERNEL
#include <kern/assert.h>
#elif CC_USE_S3
#define assert(args)  // No assert in S3
#else
#include <assert.h>
#endif

/* Provide a static assert that can be used to create compile-type failures. */
#define cc_static_assert(e,m)                                               \
    ;enum { cc_concat(static_assert_, __COUNTER__) = 1/(int)(!!(e)) }

/* Declare a struct element with a guarenteed alignment of _alignment_.
   The resulting struct can be used to create arrays that are aligned by
   a certain amount.  */
#define cc_aligned_struct(_alignment_)  \
typedef struct { \
uint8_t b[_alignment_]; \
} CC_ALIGNED(_alignment_)

/* number of array elements used in a cc_ctx_decl */
#define cc_ctx_n(_type_, _size_) ((_size_ + sizeof(_type_) - 1) / sizeof(_type_))

/* sizeof of a context declared with cc_ctx_decl */
#define cc_ctx_sizeof(_type_, _size_) sizeof(_type_[cc_ctx_n(_type_, _size_)])

/*
  1. _alloca cannot be removed becasue this header file is compiled with both MSVC++ and with clang.
  2. The _MSC_VER version of cc_ctx_decl() is not compatible with the way *_decl macros as used in CommonCrypto, AppleKeyStore and SecurityFrameworks. To observe the incompatibilities and errors, use below definition. Corecrypto itself, accepts both deinitions
      #define cc_ctx_decl(_type_, _size_, _name_)  _type_ _name_ ## _array[cc_ctx_n(_type_, (_size_))]; _type_ *_name_ = _name_ ## _array
  3. Never use sizeof() operator for the variables declared with cc_ctx_decl(), because it is not be compatible with the _MSC_VER version of cc_ctx_decl().
 */
#if defined(_MSC_VER)
#define cc_ctx_decl(_type_, _size_, _name_)  _type_ * _name_ = (_type_ *) _alloca(sizeof(_type_) * cc_ctx_n(_type_, _size_) )
#else
#define cc_ctx_decl(_type_, _size_, _name_)  _type_ _name_ [cc_ctx_n(_type_, _size_)]
#endif

/* bzero is deprecated. memset is the way to go */
/* FWIW, L4, HEXAGON and ARMCC even with gnu compatibility mode don't have bzero */
#define cc_zero(_size_,_data_) memset((_data_),0 ,(_size_))

/*!
 @brief cc_clear(len, dst) zeroizes array dst and it will not be optimized out.
 @discussion It is used to clear sensitive data, particularly when the are defined in the stack
 @param len number of bytes to be cleared in dst
 @param dst input array
 */
CC_NONNULL((2))
void cc_clear(size_t len, void *dst);

#define cc_copy(_size_, _dst_, _src_) memcpy(_dst_, _src_, _size_)

CC_INLINE CC_NONNULL((2, 3, 4))
void cc_xor(size_t size, void *r, const void *s, const void *t) {
    uint8_t *_r=(uint8_t *)r;
    const uint8_t *_s=(const uint8_t *)s;
    const uint8_t *_t=(const uint8_t *)t;
    while (size--) {
        _r[size] = _s[size] ^ _t[size];
    }
}

/*!
 @brief cc_cmp_safe(num, pt1, pt2) compares two array ptr1 and ptr2 of num bytes.
 @discussion The execution time/cycles is independent of the data and therefore guarantees no leak about the data. However, the execution time depends on num.
 @param num  number of bytes in each array
 @param ptr1 input array
 @param ptr2 input array
 @return  returns 0 if the num bytes starting at ptr1 are identical to the num bytes starting at ptr2 and 1 if they are different or if num is 0 (empty arrays).
 */
CC_NONNULL((2, 3))
int cc_cmp_safe (size_t num, const void * ptr1, const void * ptr2);

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
