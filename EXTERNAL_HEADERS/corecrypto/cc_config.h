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

//Do not set these macros to 1, unless you are developing/testing for Windows
#define CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT 0
#define CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT 0 //to be removed after <rdar://problem/26585938> port corecrypto to Windows

//this macro is used to turn on/off usage of transparent union in corecrypto
//it should be commented out in corecrypto and be used only by the software that use corecrypto
//#define CORECRYPTO_DONOT_USE_TRANSPARENT_UNION
#ifdef CORECRYPTO_DONOT_USE_TRANSPARENT_UNION
 #define CORECRYPTO_USE_TRANSPARENT_UNION 0
#else
 #define CORECRYPTO_USE_TRANSPARENT_UNION 1
#endif

#if (defined(DEBUG) && (DEBUG)) || defined(_DEBUG) //MSVC defines _DEBUG
/* CC_DEBUG is already used in CommonCrypto */
 #define CORECRYPTO_DEBUG 1
#else
 #define CORECRYPTO_DEBUG 0
#endif

// This macro can be used to enable prints when a condition in the macro "cc_require"
// is false. This is especially useful to confirm that negative testing fails
// at the intended location
#define CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS 0

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

#if (defined(ICE_FEATURES_ENABLED)) || (defined(MAVERICK) && (MAVERICK))
 #define CC_BASEBAND 1
#else
 #define CC_BASEBAND 0
#endif

#if defined(EFI) && (EFI)
 #define CC_EFI 1
#else
 #define CC_EFI 0
#endif

#if defined(IBOOT) && (IBOOT)
 #define CC_IBOOT 1
#else
 #define CC_IBOOT 0
#endif

// BB configuration
#if CC_BASEBAND

// -- ENDIANESS
 #if defined(ENDIAN_LITTLE) || (defined(__arm__) && !defined(__BIG_ENDIAN))
  #define __LITTLE_ENDIAN__
 #elif !defined(ENDIAN_BIG) && !defined(__BIG_ENDIAN)
  #error Baseband endianess not defined.
 #endif
 #define AESOPT_ENDIAN_NO_FILE

// -- Architecture
 #define CCN_UNIT_SIZE  4 // 32 bits
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

#endif // CC_BASEBAND

//CC_XNU_KERNEL_AVAILABLE indicates the availibity of XNU kernel functions,
//like what we have on OSX, iOS, tvOS, Watch OS
#if defined(__APPLE__) && defined(__MACH__)
 #define CC_XNU_KERNEL_AVAILABLE 1
#else
 #define CC_XNU_KERNEL_AVAILABLE 0
#endif

#if !defined(CCN_UNIT_SIZE)
 #if defined(__arm64__) || defined(__x86_64__)  || defined(_WIN64) 
  #define CCN_UNIT_SIZE  8
 #elif defined(__arm__) || defined(__i386__) || defined(_WIN32)
  #define CCN_UNIT_SIZE  4
 #else
  #error undefined architecture
 #endif
#endif /* !defined(CCN_UNIT_SIZE) */


//this allows corecrypto Windows development using xcode
#if defined(CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT)
 #if CORECRYPTO_SIMULATE_WINDOWS_ENVIRONMENT && CC_XNU_KERNEL_AVAILABLE && CORECRYPTO_DEBUG
  #define CC_USE_ASM 0
  #define CC_USE_HEAP_FOR_WORKSPACE 1
   #if (CCN_UNIT_SIZE==8)
    #define CCN_UINT128_SUPPORT_FOR_64BIT_ARCH 0
   #else
    #define CCN_UINT128_SUPPORT_FOR_64BIT_ARCH 1
   #endif
 #endif
#endif

#if !defined(CCN_UINT128_SUPPORT_FOR_64BIT_ARCH)
 #if defined(_WIN64) && defined(_WIN32) && (CCN_UNIT_SIZE==8)
  #define CCN_UINT128_SUPPORT_FOR_64BIT_ARCH 0
 #elif defined(_WIN32)
  #define CCN_UINT128_SUPPORT_FOR_64BIT_ARCH 1//should not be a problem
 #else
  #define CCN_UINT128_SUPPORT_FOR_64BIT_ARCH 1
 #endif
#endif

#if __clang__ || CCN_UNIT_SIZE==8
 #define CC_ALIGNED(x) __attribute__ ((aligned(x)))
#elif _MSC_VER
 #define CC_ALIGNED(x) __declspec(align(x))
#else
 #define CC_ALIGNED(x) __attribute__ ((aligned((x)>8?8:(x))))
#endif


#if   defined(__x86_64__) || defined(__i386__)
 #define CCN_IOS				   0
 #define CCN_OSX				   1
#endif 

#if CC_USE_L4 || CC_USE_S3
/* No dynamic linking allowed in L4, e.g. avoid nonlazy symbols */
/* For corecrypto kext, CC_STATIC should be undefined */
 #define CC_STATIC              1
#endif

#if !defined(CC_USE_HEAP_FOR_WORKSPACE)
 #if CC_USE_L4 || CC_IBOOT || defined(_MSC_VER)
 /* For L4, stack is too short, need to use HEAP for some computations */
 /* CC_USE_HEAP_FOR_WORKSPACE not supported for KERNEL!  */
  #define CC_USE_HEAP_FOR_WORKSPACE 1
 #else
  #define CC_USE_HEAP_FOR_WORKSPACE 0
 #endif
#endif

/* memset_s is only available in few target */
#if CC_KERNEL || CC_USE_SEPROM || defined(__CC_ARM) \
    || defined(__hexagon__) || CC_EFI
 #define CC_HAS_MEMSET_S 0
#else
 #define CC_HAS_MEMSET_S 1
#endif

// Include target conditionals if available.
#if defined(__has_include)     /* portability */
#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>
#endif /* __has_include(<TargetConditionals.h>) */
#endif /* defined(__has_include) */

//- functions implemented in assembly ------------------------------------------
//this the list of corecrypto clients that use assembly and the clang compiler
#if !(CC_XNU_KERNEL_AVAILABLE || CC_KERNEL || CC_USE_L4 || CC_IBOOT || CC_USE_SEPROM || CC_USE_S3) && !defined(_WIN32) && CORECRYPTO_DEBUG
 #warning "You are using the default corecrypto configuration, assembly optimizations may not be available for your platform"
#endif

// use this macro to strictly disable assembly regardless of cpu/os/compiler/etc
#if !defined(CC_USE_ASM)
 #if defined(_MSC_VER) || CC_LINUX || CC_EFI || CC_BASEBAND
  #define CC_USE_ASM 0
 #else
  #define CC_USE_ASM 1
 #endif
#endif

//-(1) ARM V7
#if defined(_ARM_ARCH_7) && __clang__ && CC_USE_ASM
 #define CCN_DEDICATED_SQR      1
 #define CCN_MUL_KARATSUBA      0 // no performance improvement
 #define CCN_ADD_ASM            1
 #define CCN_SUB_ASM            1
 #define CCN_MUL_ASM            0
 #define CCN_ADDMUL1_ASM        1
 #define CCN_MUL1_ASM           1
 #define CCN_CMP_ASM            1
 #define CCN_ADD1_ASM           0
 #define CCN_SUB1_ASM           0
 #define CCN_N_ASM              1
 #define CCN_SET_ASM            1
 #define CCN_SHIFT_RIGHT_ASM    1
 #define CCAES_ARM_ASM          1
 #define CCAES_INTEL_ASM        0
 #if CC_KERNEL || CC_USE_L4 || CC_IBOOT || CC_USE_SEPROM || CC_USE_S3
  #define CCAES_MUX             0
 #else
  #define CCAES_MUX             1
 #endif
 #define CCN_USE_BUILTIN_CLZ    1
 #define CCSHA1_VNG_INTEL       0
 #define CCSHA2_VNG_INTEL       0

 #if defined(__ARM_NEON__) || CC_KERNEL
  #define CCSHA1_VNG_ARMV7NEON   1
  #define CCSHA2_VNG_ARMV7NEON   1
 #else /* !defined(__ARM_NEON__) */
  #define CCSHA1_VNG_ARMV7NEON   0
  #define CCSHA2_VNG_ARMV7NEON   0
 #endif /* !defined(__ARM_NEON__) */
 #define CCSHA256_ARMV6M_ASM 0

//-(2) ARM 64
#elif (defined(__x86_64__) || defined(__i386__)) && __clang__ && CC_USE_ASM
 #define CCN_DEDICATED_SQR      1
 #define CCN_MUL_KARATSUBA      1 // 4*n CCN_UNIT extra memory required.
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

 #if (defined(__x86_64__) && CCN_UNIT_SIZE == 8)
  #define CCN_CMP_ASM            1
  #define CCN_N_ASM              1
  #define CCN_SHIFT_RIGHT_ASM    1
 #else
  #define CCN_CMP_ASM            0
  #define CCN_N_ASM              0
  #define CCN_SHIFT_RIGHT_ASM    0
 #endif

 #define CCN_ADDMUL1_ASM        0
 #define CCN_MUL1_ASM           0
 #define CCN_ADD1_ASM           0
 #define CCN_SUB1_ASM           0
 #define CCN_SET_ASM            0
 #define CCAES_ARM_ASM          0
 #define CCAES_INTEL_ASM        1
 #define CCAES_MUX              0
 #define CCN_USE_BUILTIN_CLZ    0
 #define CCSHA1_VNG_INTEL       1
 #define CCSHA2_VNG_INTEL       1
 #define CCSHA1_VNG_ARMV7NEON   0
 #define CCSHA2_VNG_ARMV7NEON   0
 #define CCSHA256_ARMV6M_ASM    0

//-(4) disable assembly  
#else
 #if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
  #define CCN_DEDICATED_SQR     1
 #else
  #define CCN_DEDICATED_SQR     0 //when assembly is off and 128-bit integers are not supported, dedicated square is off. This is the case on Windows
 #endif
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
 #define CCN_SHIFT_RIGHT_ASM    0
 #define CCAES_ARM_ASM          0
 #define CCAES_INTEL_ASM        0
 #define CCAES_MUX              0
 #define CCN_USE_BUILTIN_CLZ    0
 #define CCSHA1_VNG_INTEL       0
 #define CCSHA2_VNG_INTEL       0
 #define CCSHA1_VNG_ARMV7NEON   0
 #define CCSHA2_VNG_ARMV7NEON   0
 #define CCSHA256_ARMV6M_ASM    0

#endif

#define CC_INLINE static inline

#if CORECRYPTO_USE_TRANSPARENT_UNION
// Non null for transparent unions is ambiguous and cause problems
// for most tools (GCC and others: 23919290).
 #define CC_NONNULL_TU(N)
#else
 #define CC_NONNULL_TU(N)  CC_NONNULL(N)
#endif

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
 #define CC_UNUSED
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
