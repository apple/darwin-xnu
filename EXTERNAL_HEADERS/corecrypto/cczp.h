/*
 *  cczp.h
 *  corecrypto
 *
 *  Created on 11/16/2010
 *
 *  Copyright (c) 2010,2011,2012,2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCZP_H_
#define _CORECRYPTO_CCZP_H_

#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>

/*
 Don't use cczp_hd struct directly, except in static tables such as eliptic curve parameter
 definitions.

 Declare cczp objects using cczp_decl_n(). It allocates cc_unit arrays of the length returned by
 either cczp_nof_n() or cczp_short_nof_n().
*/

struct cczp;

typedef struct cczp *cczp_t;
typedef const struct cczp *cczp_const_t;

typedef void (*ccmod_func_t)(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s);

// keep cczp_hd and cczp structures consistent
// cczp_hd is typecasted to cczp to read EC curve params
// options field is to specify Montgomery arithmetic, bit field, etc
// make sure n is the first element see ccrsa_ctx_n macro
#define __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
    cc_size pre##n;                             \
    cc_unit pre##options;                       \
    ccmod_func_t pre##mod_prime;

#define __CCZP_ELEMENTS_DEFINITIONS(pre)    \
    __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
    cc_unit pre##ccn[];

// cczp_hd must be defined separetly without variable length array ccn[], because it is used in
// sructures such as ccdh_gp_decl_n
struct cczp_hd {
    __CCZP_HEADER_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

struct cczp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

/* Return the size of an cczp where each ccn is _size_ bytes. */
#define cczp_size(_size_) (sizeof(struct cczp) + ccn_sizeof_n(1) + 2 * (_size_))

/* Return number of units that a struct cczp needs to be in units for a prime
   size of N units.  This is large enough for all operations.  */
#define cczp_nof_n(_n_) (ccn_nof_size(sizeof(struct cczp)) + 1 + 2 * (_n_))

/* Return number of units that a struct cczp needs to be in units for a prime
   size of _n_ units.  The _short variant does not have room for CCZP_RECIP,
   so it can not be used with cczp_mod, cczp_mul, cczp_sqr. It can be used
   with cczp_add, cczp_sub, cczp_div2, cczp_mod_inv. */
#define cczp_short_nof_n(_n_) (ccn_nof_size(sizeof(struct cczp)) + (_n_))

#define cczp_decl_n(_n_, _name_) cc_ctx_decl(struct cczp, ccn_sizeof_n(cczp_nof_n(_n_)), _name_)
#define cczp_short_decl_n(_n_, _name_) \
    cc_ctx_decl(struct cczp_short, ccn_sizeof_n(cczp_short_nof_n(_n_)), _name_)

#define cczp_clear_n(_n_, _name_) cc_clear(ccn_sizeof_n(cczp_nof_n(_n_)), _name_)
#define cczp_short_clear_n(_n_, _name_) cc_clear(ccn_sizeof_n(cczp_short_nof_n(_n_)), _name_)

#define CCZP_N(ZP) ((ZP)->n)
#define CCZP_MOD(ZP) ((ZP)->mod_prime)
#define CCZP_MOD_PRIME(ZP) CCZP_MOD(ZP)
#define CCZP_PRIME(ZP) ((ZP)->ccn)
#define CCZP_RECIP(ZP) ((ZP)->ccn + CCZP_N(ZP))
#define CCZP_OPS(ZP) ((ZP)->options)
CC_CONST CC_NONNULL((1)) static inline cc_size cczp_n(cczp_const_t zp)
{
    return zp->n;
}

CC_CONST CC_NONNULL((1)) static inline cc_unit cczp_options(cczp_const_t zp)
{
    return zp->options;
}

CC_CONST CC_NONNULL((1)) static inline ccmod_func_t cczp_mod_prime(cczp_const_t zp)
{
    return zp->mod_prime;
}

CC_CONST CC_NONNULL((1)) static inline const cc_unit *cczp_prime(cczp_const_t zp)
{
    return zp->ccn;
}

/* Return a pointer to the Reciprocal or Montgomery constant of zp, which is
 allocated cczp_n(zp) + 1 units long. */
CC_CONST CC_NONNULL((1))

    static inline const cc_unit *cczp_recip(cczp_const_t zp)
{
    return zp->ccn + zp->n;
}

CC_CONST CC_NONNULL((1)) CC_INLINE size_t cczp_bitlen(cczp_const_t zp)
{
    return ccn_bitlen(cczp_n(zp), cczp_prime(zp));
}

/* Ensure both cczp_mod_prime(zp) and cczp_recip(zp) are valid. cczp_n and
   cczp_prime must have been previously initialized. */
CC_NONNULL((1))
int cczp_init(cczp_t zp);

/* Compute r = s2n mod cczp_prime(zp). Will write cczp_n(zp)
 units to r and reads 2 * cczp_n(zp) units units from s2n. If r and s2n are not
 identical they must not overlap.  Before calling this function either
 cczp_init(zp) must have been called or both CCZP_MOD_PRIME((cc_unit *)zp)
 and CCZP_RECIP((cc_unit *)zp) must be initialized some other way. */
CC_NONNULL((1, 2, 3)) void cczp_mod(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s2n);

/* Compute r = sn mod cczp_prime(zp), Will write cczp_n(zp)
 units to r and reads sn units units from s. If r and s are not
 identical they must not overlap.  Before calling this function either
 cczp_init(zp) must have been called or both CCZP_MOD_PRIME((cc_unit *)zp)
 and CCZP_RECIP((cc_unit *)zp) must be initialized some other way. */
CC_NONNULL((1, 2, 4)) int cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s);

/* Compute r = x * y mod cczp_prime(zp). Will write cczp_n(zp) units to r
   and reads cczp_n(zp) units units from both x and y. If r and x are not
   identical they must not overlap, The same holds for r and y.  Before
   calling this function either cczp_init(zp) must have been called or both
   CCZP_MOD_PRIME((cc_unit *)zp) and CCZP_RECIP((cc_unit *)zp) must be
   initialized some other way. */
CC_NONNULL((1, 2, 3, 4))
void cczp_mul(cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y);

/* Compute r = m ^ e mod cczp_prime(zp), using Montgomery ladder.
   - writes cczp_n(zp) units to r
   - reads  cczp_n(zp) units units from m and e
   - if r and m are not identical they must not overlap.
   - r and e must not overlap nor be identical.
   - before calling this function either cczp_init(zp) must have been called
   or both CCZP_MOD_PRIME((cc_unit *)zp) and CCZP_RECIP((cc_unit *)zp) must
   be initialized some other way.
 */
CC_NONNULL((1, 2, 3, 4))
int cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m, const cc_unit *e);

/* Compute r = m ^ e mod cczp_prime(zp), using Square Square Multiply Always.
 - writes cczp_n(zp) units to r
 - reads  cczp_n(zp) units units from m and e
 - if r and m are not identical they must not overlap.
 - r and e must not overlap nor be identical.
 - before calling this function either cczp_init(zp) must have been called
 or both CCZP_MOD_PRIME((cc_unit *)zp) and CCZP_RECIP((cc_unit *)zp) must
 be initialized some other way.

 Important: This function is intented to be constant time but is more likely
    to leak information due to memory cache. Only used with randomized input
 */
CC_NONNULL((1, 2, 3, 4))
int cczp_power_ssma(cczp_const_t zp, cc_unit *r, const cc_unit *m, const cc_unit *e);

/*!
 @brief cczp_inv(zp, r, x) computes r = x^-1 (mod p) , where p=cczp_prime(zp).
 @discussion It is a general function and works for any p. It validates the inputs. r and x can
 overlap. It writes n =cczp_n(zp) units to r, and read n units units from x and p. The output r is
 overwriten only if the inverse is correctly computed. This function is not constant time in
 absolute sense, but it does not have data dependent 'if' statements in the code.
 @param zp  The input zp. cczp_n(zp) and cczp_prime(zp) need to be valid. cczp_init(zp) need not to
 be called before invoking cczp_inv().
 @param x input big integer
 @param r output big integer
 @return  0 if inverse exists and correctly computed.
 */
CC_NONNULL((1, 2, 3))
int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*!
 @brief cczp_inv_odd(zp, r, x) computes r = x^-1 (mod p) , where p=cczp_prime(zp) is an odd number.
 @discussion  r and x can overlap.
 @param zp  The input zp. cczp_n(zp) and cczp_prime(zp) need to be valid. cczp_init(zp) need not to
 be called before invoking.
 @param x input big integer
 @param r output big integer
 @return  0 if successful
 */
CC_NONNULL((1, 2, 3)) int cczp_inv_odd(cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*!
 @brief cczp_inv_field(zp, r, x) computes r = x^-1 (mod p) , where p=cczp_prime(zp) is a prime
 number number.
 @discussion r and x must NOT overlap. The excution time of the function is independent to the value
 of the input x. It works only if p is a field. That is, when p is a prime. It supports Montgomery
 and non-Montgomery form of zp. It leaks the value of the prime and should only be used be used for
 public (not secret) primes (ex. Elliptic Curves)

 @param zp  The input zp. cczp_n(zp) and cczp_prime(zp) need to be valid. cczp_init(zp) need not to
 be called before invoking cczp_inv_field().
 @param x input big unteger
 @param r output big integer
 @return  0 if inverse exists and correctly computed.
 */
CC_NONNULL((1, 2, 3))
int cczp_inv_field(cczp_const_t zp, cc_unit *r, const cc_unit *x);

#endif /* _CORECRYPTO_CCZP_H_ */
