/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZP_H_
#define _CORECRYPTO_CCZP_H_

#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>

/*
 Don't use cczp_hd struct directly, except in static tables such as eliptic curve parameter
 definitions.

 Declare cczp objects using cczp_decl_n(). It allocates cc_unit arrays of the length returned by
 cczp_nof_n().
*/

struct cczp;

typedef struct cczp *cczp_t;
typedef const struct cczp *cczp_const_t;

struct cczp_funcs;
typedef const struct cczp_funcs *cczp_funcs_t;

// keep cczp_hd and cczp structures consistent
// cczp_hd is typecasted to cczp to read EC curve params
// make sure n is the first element see ccrsa_ctx_n macro
#define __CCZP_HEADER_ELEMENTS_DEFINITIONS(pre) \
    cc_size pre##n;                             \
    cc_unit pre##bitlen;                        \
    cczp_funcs_t pre##funcs;

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
   size of _n_ units. */
#define cczp_decl_n(_n_, _name_) cc_ctx_decl(struct cczp, ccn_sizeof_n(cczp_nof_n(_n_)), _name_)
#define cczp_clear_n(_n_, _name_) cc_clear(ccn_sizeof_n(cczp_nof_n(_n_)), _name_)

#define CCZP_N(ZP) ((ZP)->n)
#define CCZP_PRIME(ZP) ((ZP)->ccn)
#define CCZP_BITLEN(ZP) ((ZP)->bitlen)
#define CCZP_RECIP(ZP) ((ZP)->ccn + CCZP_N(ZP))
CC_NONNULL((1)) CC_INLINE cc_size cczp_n(cczp_const_t zp)
{
    return zp->n;
}

CC_NONNULL((1)) CC_INLINE const cc_unit *cczp_prime(cczp_const_t zp)
{
    return zp->ccn;
}

CC_NONNULL((1)) CC_INLINE size_t cczp_bitlen(cczp_const_t zp)
{
    cc_assert(ccn_bitlen(cczp_n(zp), cczp_prime(zp)) == CCZP_BITLEN(zp));
    return (size_t)CCZP_BITLEN(zp);
}

/* Return a pointer to the Reciprocal or Montgomery constant of zp, which is
 allocated cczp_n(zp) + 1 units long. */
CC_NONNULL((1)) CC_INLINE const cc_unit *cczp_recip(cczp_const_t zp)
{
    return zp->ccn + zp->n;
}

/* Ensure both cczp_mod_prime(zp) and cczp_recip(zp) are valid. cczp_n and
   cczp_prime must have been previously initialized. The reciprocal will
   be computed and set. */
CC_NONNULL((1))
int cczp_init(cczp_t zp);

/*! @function cczp_init_with_recip
 @abstract Initializes a cczp struct with a given reciprocal.

 @param zp    Pointer to a cczp struct.
 @param recip Reciprocal for zp's prime.
 */
CC_NONNULL((1, 2))
void cczp_init_with_recip(cczp_t zp, const cc_unit *recip);

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

#endif /* _CORECRYPTO_CCZP_H_ */
