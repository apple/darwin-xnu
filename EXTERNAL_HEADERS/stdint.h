/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 *
 * We build on <machine/types.h> rather than <sys/types.h> in order to
 * minimize the global namespace pollution (i.e., we'd like to define
 * *only* those identifiers that the C standard mandates should be
 * defined by <stdint.h>).   Using <machine/types.h> means that (at
 * least as of January 2001) all of the extra macros that do get
 * #defined by #include'ing <stdint.h> are in the implementor's
 * namespace ("_[A-Z].*" or "__.*").
 *
 * The reason that we do #include the relevant ...types.h instead of
 * creating several "competing" typedefs is to make header collisions
 * less likely during the transition to C99.
 *
 * Caveat:  There are still five extra typedef's defined by doing it
 * this way:  "u_int{8,16,32,64}_t" and "register_t".  Might be
 * fixable via pre- and post- #defines, but probably not worth it.
 */

#ifndef _STDINT_H_
#define _STDINT_H_

#include <machine/types.h>

/* from ISO/IEC 988:1999 spec */

/* 7.18.1.1 Exact-width integer types */
                                         /* int8_t is defined in <machine/types.h> */
                                         /* int16_t is defined in <machine/types.h> */
                                         /* int32_t is defined in <machine/types.h> */
                                         /* int64_t is defined in <machine/types.h> */
typedef u_int8_t              uint8_t;   /* u_int8_t is defined in <machine/types.h> */
typedef u_int16_t            uint16_t;   /* u_int16_t is defined in <machine/types.h> */
typedef u_int32_t            uint32_t;   /* u_int32_t is defined in <machine/types.h> */
typedef u_int64_t            uint64_t;   /* u_int64_t is defined in <machine/types.h> */


/* 7.18.1.2 Minumun-width integer types */
typedef int8_t           int_least8_t;
typedef int16_t         int_least16_t;
typedef int32_t         int_least32_t;
typedef int64_t         int_least64_t;
typedef uint8_t         uint_least8_t;
typedef uint16_t       uint_least16_t;
typedef uint32_t       uint_least32_t;
typedef uint64_t       uint_least64_t;


/* 7.18.1.3 Fastest-width integer types */
typedef int8_t            int_fast8_t;
typedef int16_t          int_fast16_t;
typedef int32_t          int_fast32_t;
typedef int64_t          int_fast64_t;
typedef uint8_t          uint_fast8_t;
typedef uint16_t        uint_fast16_t;
typedef uint32_t        uint_fast32_t;
typedef uint64_t        uint_fast64_t;


/* 7.18.1.4 Integer types capable of hgolding object pointers */
                                        /* intptr_t is defined in <machine/types.h> */
                                        /* uintptr_t is defined in <machine/types.h> */


/* 7.18.1.5 Greatest-width integer types */
typedef long long                intmax_t;
typedef unsigned long long      uintmax_t;


/* "C++ implementations should define these macros only when
 *  __STDC_LIMIT_MACROS is defined before <stdint.h> is included."
 * In other words, if C++, then __STDC_LIMIT_MACROS enables the
 * macros below.  (Note that there also exists a different enabling
 * macro (__STDC_CONSTANT_MACROS) for the last few, below.)
 */
#if (! defined(__cplusplus)) || defined(__STDC_LIMIT_MACROS)


/* 7.18.2 Limits of specified-width integer types:
 *   These #defines specify the minimum and maximum limits
 *   of each of the types declared above.
 */


/* 7.18.2.1 Limits of exact-width integer types */
#define INT8_MIN         (-127-1)
#define INT16_MIN        (-32767-1)
#define INT32_MIN        (-2147483647-1)
#define INT64_MIN        (-9223372036854775807LL-1LL)

#define INT8_MAX         +127
#define INT16_MAX        +32767
#define INT32_MAX        +2147483647
#define INT64_MAX        +9223372036854775807LL

#define UINT8_MAX         255
#define UINT16_MAX        65535
#define UINT32_MAX        4294967295U
#define UINT64_MAX        18446744073709551615ULL

/* 7.18.2.2 Limits of minimum-width integer types */
#define INT_LEAST8_MIN    INT8_MIN
#define INT_LEAST16_MIN   INT16_MIN
#define INT_LEAST32_MIN   INT32_MIN
#define INT_LEAST64_MIN   INT64_MIN

#define INT_LEAST8_MAX    INT8_MAX
#define INT_LEAST16_MAX   INT16_MAX
#define INT_LEAST32_MAX   INT32_MAX
#define INT_LEAST64_MAX   INT64_MAX

#define UINT_LEAST8_MAX   UINT8_MAX
#define UINT_LEAST16_MAX  UINT16_MAX
#define UINT_LEAST32_MAX  UINT32_MAX
#define UINT_LEAST64_MAX  UINT64_MAX

/* 7.18.2.3 Limits of fastest minimum-width integer types */
#define INT_FAST8_MIN     INT8_MIN
#define INT_FAST16_MIN    INT16_MIN
#define INT_FAST32_MIN    INT32_MIN
#define INT_FAST64_MIN    INT64_MIN

#define INT_FAST8_MAX     INT8_MAX
#define INT_FAST16_MAX    INT16_MAX
#define INT_FAST32_MAX    INT32_MAX
#define INT_FAST64_MAX    INT64_MAX

#define UINT_FAST8_MAX    UINT8_MAX
#define UINT_FAST16_MAX   UINT16_MAX
#define UINT_FAST32_MAX   UINT32_MAX
#define UINT_FAST64_MAX   UINT64_MAX

/* 7.18.2.4 Limits of integer types capable of holding object pointers */
#if defined(__LP64__)
#define INTPTR_MIN        INT64_MIN
#define INTPTR_MAX        INT64_MAX
#define UINTPTR_MAX       UINT64_MAX
#else
#define INTPTR_MIN        INT32_MIN
#define INTPTR_MAX        INT32_MAX
#define UINTPTR_MAX       UINT32_MAX
#endif

/* 7.18.2.5 Limits of greatest-width integer types */
#define INTMAX_MIN        INT64_MIN
#define INTMAX_MAX        INT64_MAX

#define UINTMAX_MAX       UINT64_MAX

/* 7.18.3 "Other" */
#if defined(__LP64__)
#define PTRDIFF_MIN       INT64_MIN
#define PTRDIFF_MAX       INT64_MAX
#else
#define PTRDIFF_MIN       INT32_MIN
#define PTRDIFF_MAX       INT32_MAX
#endif
/* We have no sig_atomic_t yet, so no SIG_ATOMIC_{MIN,MAX}.
   Should end up being {-127,127} or {0,255} ... or bigger.
   My bet would be on one of {U}INT32_{MIN,MAX}. */

#define SIZE_MAX          UINT32_MAX

#define WCHAR_MAX         INT32_MAX

/* We have no wint_t yet, so no WINT_{MIN,MAX}.
   Should end up being {U}INT32_{MIN,MAX}, depending.  */


#endif /* if C++, then __STDC_LIMIT_MACROS enables the above macros */

/* "C++ implementations should define these macros only when
 *  __STDC_CONSTANT_MACROS is defined before <stdint.h> is included."
 */ 
#if (! defined(__cplusplus)) || defined(__STDC_CONSTANT_MACROS)

/* 7.18.4 Macros for integer constants */
#define INT8_C(v)    ((int8_t)v)
#define INT16_C(v)   ((int16_t)v)
#define INT32_C(v)   (v ## L)
#define INT64_C(v)   (v ## LL)

#define UINT8_C(v)   ((uint8_t)v)
#define UINT16_C(v)  ((uint16_t)v)
#define UINT32_C(v)  (v ## UL)
#define UINT64_C(v)  (v ## ULL)

#define INTMAX_C(v)  (v ## LL)
#define UINTMAX_C(v) (v ## ULL)

#endif /* if C++, then __STDC_CONSTANT_MACROS enables the above macros */

#endif /* _STDINT_H_ */
