/*
 *  cc_config.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 10/18/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */
#ifndef _CORECRYPTO_CC_CONFIG_H_
#define _CORECRYPTO_CC_CONFIG_H_

#if !defined(CCN_UNIT_SIZE)
#if defined(__x86_64__)
#define CCN_UNIT_SIZE  8
#elif defined(__arm__) || defined(__i386__)
#define CCN_UNIT_SIZE  4
#else
#define CCN_UNIT_SIZE  2
#endif
#endif /* !defined(CCN_UNIT_SIZE) */

/* No dynamic linking allowed in L4, e.g. avoid nonlazy symbols */
/* For corecrypto kext, CC_STATIC should be 0 */

#if   defined(__x86_64__) || defined(__i386__)

/* These assembly routines only work for a single CCN_UNIT_SIZE. */
#if (defined(__x86_64__) && CCN_UNIT_SIZE == 8) || (defined(__i386__) && CCN_UNIT_SIZE == 4)
#define CCN_ADD_ASM            1
#define CCN_SUB_ASM            1
#define CCN_MUL_ASM            1
#else
#define CCN_ADD_ASM            0
#define CCN_SUB_ASM            0
#define CCN_MUL_ASM            0
#endif

#define CCN_ADDMUL1_ASM        0
#define CCN_MUL1_ASM           0
#define CCN_CMP_ASM            0
#define CCN_ADD1_ASM           0
#define CCN_SUB1_ASM           0
#define CCN_N_ASM              0
#define CCN_SET_ASM            0
#define CCAES_ARM              0
#define CCAES_INTEL            1
#define CCN_USE_BUILTIN_CLZ    0
#define CCSHA1_VNG_INTEL       1
#define CCSHA2_VNG_INTEL       1
#define CCSHA1_VNG_ARMV7NEON   0
#define CCSHA2_VNG_ARMV7NEON   0

#else

#define CCN_ADD_ASM            0
#define CCN_SUB_ASM            0
#define CCN_MUL_ASM            0
#define CCN_ADDMUL1_ASM        0
#define CCN_MUL1_ASM           0
#define CCN_CMP_ASM            0
#define CCN_ADD1_ASM           0
#define CCN_SUB1_ASM           0
#define CCN_N_ASM              0
#define CCN_SET_ASM            0
#define CCAES_ARM              0
#define CCAES_INTEL            0
#define CCN_USE_BUILTIN_CLZ    0
#define CCSHA1_VNG_INTEL       0
#define CCSHA2_VNG_INTEL       0
#define CCSHA1_VNG_ARMV7NEON   0
#define CCSHA2_VNG_ARMV7NEON   0

#endif /* !defined(__i386__) */

#define CCN_N_INLINE           0
#define CCN_CMP_INLINE         0

#define CC_INLINE static inline

#ifdef __GNUC__
#define CC_NORETURN __attribute__((__noreturn__))
#define CC_NOTHROW __attribute__((__nothrow__))
#define CC_NONNULL(N) __attribute__((__nonnull__ N))
#define CC_NONNULL1 __attribute__((__nonnull__(1)))
#define CC_NONNULL2 __attribute__((__nonnull__(2)))
#define CC_NONNULL3 __attribute__((__nonnull__(3)))
#define CC_NONNULL4 __attribute__((__nonnull__(4)))
#define CC_NONNULL5 __attribute__((__nonnull__(5)))
#define CC_NONNULL6 __attribute__((__nonnull__(6)))
#define CC_NONNULL7 __attribute__((__nonnull__(7)))
#define CC_NONNULL_ALL __attribute__((__nonnull__))
#define CC_SENTINEL __attribute__((__sentinel__))
#define CC_CONST __attribute__((__const__))
#define CC_PURE __attribute__((__pure__))
#define CC_WARN_RESULT __attribute__((__warn_unused_result__))
#define CC_MALLOC __attribute__((__malloc__))
#define CC_UNUSED __attribute__((unused))
#else /* !__GNUC__ */
/*! @parseOnly */
#define CC_NORETURN
/*! @parseOnly */
#define CC_NOTHROW
/*! @parseOnly */
#define CC_NONNULL1
/*! @parseOnly */
#define CC_NONNULL2
/*! @parseOnly */
#define CC_NONNULL3
/*! @parseOnly */
#define CC_NONNULL4
/*! @parseOnly */
#define CC_NONNULL5
/*! @parseOnly */
#define CC_NONNULL6
/*! @parseOnly */
#define CC_NONNULL7
/*! @parseOnly */
#define CC_NONNULL_ALL
/*! @parseOnly */
#define CC_SENTINEL
/*! @parseOnly */
#define CC_CONST
/*! @parseOnly */
#define CC_PURE
/*! @parseOnly */
#define CC_WARN_RESULT
/*! @parseOnly */
#define CC_MALLOC
#endif /* !__GNUC__ */

#endif /* _CORECRYPTO_CC_CONFIG_H_ */
