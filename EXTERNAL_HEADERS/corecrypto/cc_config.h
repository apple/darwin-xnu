/*
 *  cc_config.h
 *  corecrypto
 *
 *  Created on 11/16/2010
 *
 *  Copyright (c) 2010,2011,2012,2013,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CC_CONFIG_H_
#define _CORECRYPTO_CC_CONFIG_H_

/* A word about configuration macros:
 
    Conditional configuration macros specific to corecrypto should be named CORECRYPTO_xxx
    or CCxx_yyy and be defined to be either 0 or 1 in this file. You can add an 
    #ifndef #error construct at the end of this file to make sure it's always defined.

    They should always be tested using the #if directive, never the #ifdef directive.

    No other conditional macros shall ever be used (except in this file)

    Configuration Macros that are defined outside of corecrypto (eg: KERNEL, DEBUG, ...)
    shall only be used in this file to define CCxxx macros.
 
    External macros should be assumed to be either undefined, defined with no value,
    or defined as true or false. We shall strive to build with -Wundef whenever possible,
    so the following construct should be used to test external macros in this file:
  
         #if defined(DEBUG) && (DEBUG)
         #define CORECRYPTO_DEBUG 1
         #else
         #define CORECRYPTO_DEBUG 0
         #endif
  

    It is acceptable to define a conditional CC_xxxx macro in an implementation file,
    to be used only in this file.
 
    The current code is not guaranteed to follow those rules, but should be fixed to.
 
    Corecrypto requires GNU and C99 compatibility.
    Typically enabled by passing --gnu --c99 to the compiler (eg. armcc)

*/

#if (defined(DEBUG) && (DEBUG))
/* CC_DEBUG is already used in CommonCrypto */
#define CORECRYPTO_DEBUG 1
#else
#define CORECRYPTO_DEBUG 0
#endif

#if defined(KERNEL) && (KERNEL)
#define CC_KERNEL 1 // KEXT, XNU repo or kernel components such as AppleKeyStore
#else
#define CC_KERNEL 0
#endif

// LINUX_BUILD_TEST is for sanity check of the configuration
// > xcodebuild -scheme "corecrypto_test" OTHER_CFLAGS="$(values) -DLINUX_BUILD_TEST"
#if defined(__linux__) || defined(LINUX_BUILD_TEST)
#define CC_LINUX 1
#else
#define CC_LINUX 0
#endif

#if defined(USE_L4) && (USE_L4)
#define CC_USE_L4 1
#else
#define CC_USE_L4 0
#endif

#if defined(USE_SEPROM) && (USE_SEPROM)
#define CC_USE_SEPROM 1
#else
#define CC_USE_SEPROM 0
#endif

#if defined(USE_S3) && (USE_S3)
#define CC_USE_S3 1
#else
#define CC_USE_S3 0
#endif

#if defined(MAVERICK) && (MAVERICK)
#define CC_MAVERICK 1
#else
#define CC_MAVERICK 0
#endif

#if defined(IBOOT) && (IBOOT)
#define CC_IBOOT 1
#else
#define CC_IBOOT 0
#endif

// BB configuration
#if CC_MAVERICK

// -- ENDIANESS
#if defined(ENDIAN_LITTLE) || (defined(__arm__) && !defined(__BIG_ENDIAN))
#define __LITTLE_ENDIAN__
#elif !defined(ENDIAN_BIG) && !defined(__BIG_ENDIAN)
#error Baseband endianess not defined.
#endif
#define AESOPT_ENDIAN_NO_FILE

// -- Architecture
#define CCN_UNIT_SIZE  4 // 32 bits
#define aligned(x) aligned((x)>8?8:(x))   // Alignment on 8 bytes max
#define SAFE_IO          // AES support for unaligned Input/Output

// -- External function
#define assert ASSERT   // sanity

// -- Warnings
// Ignore irrelevant warnings after verification
// #1254-D: arithmetic on pointer to void or function type
// #186-D: pointless comparison of unsigned integer with zero
// #546-D: transfer of control bypasses initialization of
#if   defined(__GNUC__)
// warning: pointer of type 'void *' used in arithmetic
#pragma GCC diagnostic ignored "-Wpointer-arith"
#endif // arm or gnuc

#endif // MAVERICK

#if !defined(CCN_UNIT_SIZE)
#if defined(__arm64__) || defined(__x86_64__)
#define CCN_UNIT_SIZE  8
#elif defined(__arm__) || defined(__i386__)
#define CCN_UNIT_SIZE  4
#else
#define CCN_UNIT_SIZE  2
#endif
#endif /* !defined(CCN_UNIT_SIZE) */

#if   defined(__x86_64__) || defined(__i386__)
#define CCN_IOS				   0
#define CCN_OSX				   1
#endif 

#if CC_USE_L4 || CC_USE_S3
/* No dynamic linking allowed in L4, e.g. avoid nonlazy symbols */
/* For corecrypto kext, CC_STATIC should be undefined */
#define CC_STATIC              1
#endif

#if CC_USE_L4 || CC_IBOOT
/* For L4, stack is too short, need to use HEAP for some computations */
/* CC_USE_HEAP_FOR_WORKSPACE not supported for KERNEL!  */
#define CC_USE_HEAP_FOR_WORKSPACE 1
#else
#define CC_USE_HEAP_FOR_WORKSPACE 0
#endif

/* L4 do not have bzero, neither does hexagon of ARMCC even with gnu compatibility mode */
#if CC_USE_L4 || defined(__CC_ARM) || defined(__hexagon__)
#define CC_HAS_BZERO 0
#else
#define CC_HAS_BZERO 1
#endif

/* memset_s is only available in few target */
#if CC_USE_L4 || CC_KERNEL || CC_IBOOT || CC_USE_SEPROM || defined(__CC_ARM) || defined(__hexagon__)
#define CC_HAS_MEMSET_S 0
#else
#define CC_HAS_MEMSET_S 1
#endif


#if defined(__CC_ARM) || defined(__hexagon__) || CC_LINUX || defined(__NO_ASM__)
// ARMASM.exe does not to like the file syntax of the asm implementation
#define CCN_DEDICATED_SQR      1
#define CCN_MUL_KARATSUBA      1 // 4*n CCN_UNIT extra memory required.
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
#if !defined(__NO_ASM__)
#define CCSHA1_VNG_INTEL       0
#define CCSHA2_VNG_INTEL       0
#define CCSHA1_VNG_ARMV7NEON   0
#define CCSHA2_VNG_ARMV7NEON   0
#endif
#define CCAES_MUX              0

#elif defined(__x86_64__) || defined(__i386__)
#define CCN_DEDICATED_SQR      1
#define CCN_MUL_KARATSUBA      1 // 4*n CCN_UNIT extra memory required.
/* These assembly routines only work for a single CCN_UNIT_SIZE. */
#if (defined(__x86_64__) && CCN_UNIT_SIZE == 8) || (defined(__i386__) && CCN_UNIT_SIZE == 4)
#define CCN_ADD_ASM            1
#define CCN_SUB_ASM            1
#define CCN_MUL_ASM            0
#else
#define CCN_ADD_ASM            0
#define CCN_SUB_ASM            0
#define CCN_MUL_ASM            0
#endif

#if (defined(__x86_64__) && CCN_UNIT_SIZE == 8)
#define CCN_CMP_ASM            1
#define CCN_N_ASM              1
#else
#define CCN_CMP_ASM            0
#define CCN_N_ASM              0
#endif

#define CCN_ADDMUL1_ASM        0
#define CCN_MUL1_ASM           0
#define CCN_ADD1_ASM           0
#define CCN_SUB1_ASM           0
#define CCN_SET_ASM            0
#define CCAES_ARM              0
#define CCAES_INTEL            1
#define CCAES_MUX              0
#define CCN_USE_BUILTIN_CLZ    0
#define CCSHA1_VNG_INTEL       1
#define CCSHA2_VNG_INTEL       1
#define CCSHA1_VNG_ARMV7NEON   0
#define CCSHA2_VNG_ARMV7NEON   0

#else
#define CCN_DEDICATED_SQR      1
#define CCN_MUL_KARATSUBA      1 // 4*n CCN_UNIT extra memory required.
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
#define CCAES_MUX              0
#define CCN_USE_BUILTIN_CLZ    0
#define CCSHA1_VNG_INTEL       0
#define CCSHA2_VNG_INTEL       0
#define CCSHA1_VNG_ARMV7NEON   0
#define CCSHA2_VNG_ARMV7NEON   0

#endif /* !defined(__i386__) */

#define CC_INLINE static inline

#ifdef __GNUC__
#define CC_NORETURN __attribute__((__noreturn__))
#define CC_NOTHROW __attribute__((__nothrow__))
// Transparent Union
#if defined(__CC_ARM) || defined(__hexagon__)
#define CC_NONNULL_TU(N)
#else
#define CC_NONNULL_TU(N) __attribute__((__nonnull__ N))
#endif
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
#define CC_UNUSED
/*! @parseOnly */
#define CC_NONNULL_TU(N)
/*! @parseOnly */
#define CC_NONNULL(N)
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
