/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright 1995 NeXT Computer, Inc. All rights reserved. */
/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)cdefs.h	8.8 (Berkeley) 1/9/95
 */

#ifndef	_CDEFS_H_
#define	_CDEFS_H_

#if defined(__cplusplus)
#define	__BEGIN_DECLS	extern "C" {
#define	__END_DECLS	}
#else
#define	__BEGIN_DECLS
#define	__END_DECLS
#endif

/*
 * The __CONCAT macro is used to concatenate parts of symbol names, e.g.
 * with "#define OLD(foo) __CONCAT(old,foo)", OLD(foo) produces oldfoo.
 * The __CONCAT macro is a bit tricky -- make sure you don't put spaces
 * in between its arguments.  __CONCAT can also concatenate double-quoted
 * strings produced by the __STRING macro, but this only works with ANSI C.
 */
#if defined(__STDC__) || defined(__cplusplus)
#define	__P(protos)	protos		/* full-blown ANSI C */
#define	__CONCAT(x,y)	x ## y
#define	__STRING(x)	#x

#define	__const		const		/* define reserved names to standard */
#define	__signed	signed
#define	__volatile	volatile
#if defined(__cplusplus)
#define	__inline	inline		/* convert to C++ keyword */
#else
#ifndef __GNUC__
#define	__inline			/* delete GCC keyword */
#endif /* !__GNUC__ */
#endif /* !__cplusplus */

#else	/* !(__STDC__ || __cplusplus) */
#define	__P(protos)	()		/* traditional C preprocessor */
#define	__CONCAT(x,y)	x/**/y
#define	__STRING(x)	"x"

#ifndef __GNUC__
#define	__const				/* delete pseudo-ANSI C keywords */
#define	__inline
#define	__signed
#define	__volatile
#endif	/* !__GNUC__ */

/*
 * In non-ANSI C environments, new programs will want ANSI-only C keywords
 * deleted from the program and old programs will want them left alone.
 * When using a compiler other than gcc, programs using the ANSI C keywords
 * const, inline etc. as normal identifiers should define -DNO_ANSI_KEYWORDS.
 * When using "gcc -traditional", we assume that this is the intent; if
 * __GNUC__ is defined but __STDC__ is not, we leave the new keywords alone.
 */
#ifndef	NO_ANSI_KEYWORDS
#define	const		__const			/* convert ANSI C keywords */
#define	inline		__inline
#define	signed		__signed
#define	volatile	__volatile
#endif /* !NO_ANSI_KEYWORDS */
#endif /* !(__STDC__ || __cplusplus) */

/*
 * GCC1 and some versions of GCC2 declare dead (non-returning) and
 * pure (no side effects) functions using "volatile" and "const";
 * unfortunately, these then cause warnings under "-ansi -pedantic".
 * GCC2 uses a new, peculiar __attribute__((attrs)) style.  All of
 * these work for GNU C++ (modulo a slight glitch in the C++ grammar
 * in the distribution version of 2.5.5).
 */
#if defined(__MWERKS__) && (__MWERKS__ > 0x2400)
	/* newer Metrowerks compilers support __attribute__() */
#elif __GNUC__ > 2 || __GNUC__ == 2 && __GNUC_MINOR__ >= 5
#define	__dead2		__attribute__((__noreturn__))
#define	__pure2		__attribute__((__const__))
#if __GNUC__ == 2 && __GNUC_MINOR__ >= 5 && __GNUC_MINOR__ < 7
#define	__unused	/* no attribute */
#else
#define	__unused	__attribute__((__unused__))
#endif
#else
#define	__attribute__(x)	/* delete __attribute__ if non-gcc or gcc1 */
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
/* __dead and __pure are depreciated.  Use __dead2 and __pure2 instead */
#define	__dead		__volatile
#define	__pure		__const
#endif
#endif

/* Delete pseudo-keywords wherever they are not available or needed. */
#ifndef __dead
#define	__dead
#define	__pure
#endif
#ifndef __dead2
#define	__dead2
#define	__pure2
#define	__unused
#endif

/*
 * GCC 2.95 provides `__restrict' as an extension to C90 to support the
 * C99-specific `restrict' type qualifier.  We happen to use `__restrict' as
 * a way to define the `restrict' type qualifier without disturbing older
 * software that is unaware of C99 keywords.
 */
#if !(__GNUC__ == 2 && __GNUC_MINOR__ == 95)
#if __STDC_VERSION__ < 199901
#define __restrict
#else
#define __restrict	restrict
#endif
#endif

/*
 * Compiler-dependent macros to declare that functions take printf-like
 * or scanf-like arguments.  They are null except for versions of gcc
 * that are known to support the features properly.  Functions declared
 * with these attributes will cause compilation warnings if there is a
 * mismatch between the format string and subsequent function parameter
 * types.
 */
#if __GNUC__ > 2 || __GNUC__ == 2 && __GNUC_MINOR__ >= 7
#define __printflike(fmtarg, firstvararg) \
		__attribute__((__format__ (__printf__, fmtarg, firstvararg)))
#define __scanflike(fmtarg, firstvararg) \
		__attribute__((__format__ (__scanf__, fmtarg, firstvararg)))
#else
#define __printflike(fmtarg, firstvararg)
#define __scanflike(fmtarg, firstvararg)
#endif

#define __IDSTRING(name,string) static const char name[] __unused = string

#ifndef __COPYRIGHT
#define __COPYRIGHT(s) __IDSTRING(copyright,s)
#endif

#ifndef __RCSID
#define __RCSID(s) __IDSTRING(rcsid,s)
#endif

#ifndef __SCCSID
#define __SCCSID(s) __IDSTRING(sccsid,s)
#endif

#ifndef __PROJECT_VERSION
#define __PROJECT_VERSION(s) __IDSTRING(project_version,s)
#endif

/*
 * COMPILATION ENVIRONMENTS
 *
 * DEFAULT	By default newly complied code will get POSIX APIs plus
 *		Apple API extensions in scope.
 *
 *		Most users will use this compilation environment to avoid
 *		behavioral differences between 32 and 64 bit code.
 *
 * LEGACY	Defining _NONSTD_SOURCE will get pre-POSIX APIs plus Apple
 *		API extensions in scope.
 *
 *		This is generally equivalent to the Tiger release compilation
 *		environment, except that it cannot be applied to 64 bit code;
 *		its use is discouraged.
 *
 *		We expect this environment to be deprecated in the future.
 *
 * STRICT	Defining _POSIX_C_SOURCE or _XOPEN_SOURCE restricts the
 *		available APIs to exactly the set of APIs defined by the
 *		corresponding standard, based on the value defined.
 *
 *		A correct, portable definition for _POSIX_C_SOURCE is 200112L.
 *		A correct, portable definition for _XOPEN_SOURCE is 600L.
 *
 *		Apple API extensions are not visible in this environment,
 *		which can cause Apple specific code to fail to compile,
 *		or behave incorrectly if prototypes are not in scope or
 *		warnings about missing prototypes are not enabled or ignored.
 *
 * In any compilation environment, for correct symbol resolution to occur,
 * function prototypes must be in scope.  It is recommended that all Apple
 * tools users add either the "-Wall" or "-Wimplicit-function-declaration"
 * compiler flags to their projects to be warned when a function is being
 * used without a prototype in scope.
 */

/* These settings are particular to each product. */
#ifdef KERNEL
#define __DARWIN_ONLY_64_BIT_INO_T	0
#define __DARWIN_ONLY_UNIX_CONFORMANCE	0
#define __DARWIN_ONLY_VERS_1050		0
#define	__DARWIN_SUF_DARWIN10	"_darwin10"
#define	__DARWIN10_ALIAS(sym)	__asm("_" __STRING(sym) __DARWIN_SUF_DARWIN10)
#else /* !KERNEL */
#ifdef PRODUCT_AppleTV
/* Product: AppleTV */
#define __DARWIN_ONLY_64_BIT_INO_T	1
#define __DARWIN_ONLY_UNIX_CONFORMANCE	1
#define __DARWIN_ONLY_VERS_1050		1
#endif /* PRODUCT_AppleTV */
#ifdef PRODUCT_iPhone
/* Product: iPhone */
#define __DARWIN_ONLY_64_BIT_INO_T	1
#define __DARWIN_ONLY_UNIX_CONFORMANCE	1
#define __DARWIN_ONLY_VERS_1050		1
#endif /* PRODUCT_iPhone */
#ifdef PRODUCT_MacOSX
/* Product: MacOSX */
#define __DARWIN_ONLY_64_BIT_INO_T	0
/* #undef __DARWIN_ONLY_UNIX_CONFORMANCE (automatically set for 64-bit) */
#define __DARWIN_ONLY_VERS_1050		0
#endif /* PRODUCT_MacOSX */
#endif /* KERNEL */

/*
 * The __DARWIN_ALIAS macros are used to do symbol renaming; they allow
 * legacy code to use the old symbol, thus maintaining binary compatibility
 * while new code can use a standards compliant version of the same function.
 *
 * __DARWIN_ALIAS is used by itself if the function signature has not
 * changed, it is used along with a #ifdef check for __DARWIN_UNIX03
 * if the signature has changed.  Because the __LP64__ environment
 * only supports UNIX03 semantics it causes __DARWIN_UNIX03 to be
 * defined, but causes __DARWIN_ALIAS to do no symbol mangling.
 *
 * As a special case, when XCode is used to target a specific version of the
 * OS, the manifest constant __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
 * will be defined by the compiler, with the digits representing major version
 * time 100 + minor version times 10 (e.g. 10.5 := 1050).  If we are targeting
 * pre-10.5, and it is the default compilation environment, revert the
 * compilation environment to pre-__DARWIN_UNIX03.
 */
#if !defined(__DARWIN_ONLY_UNIX_CONFORMANCE)
#  if defined(__LP64__)
#    define __DARWIN_ONLY_UNIX_CONFORMANCE 1
#  else /* !__LP64__ */
#    define __DARWIN_ONLY_UNIX_CONFORMANCE 0
#  endif /* __LP64__ */
#endif /* !__DARWIN_ONLY_UNIX_CONFORMANCE */

#if !defined(__DARWIN_UNIX03)
#  if defined(KERNEL)
#    define __DARWIN_UNIX03	0
#  elif __DARWIN_ONLY_UNIX_CONFORMANCE
#    if defined(_NONSTD_SOURCE)
#      error "Can't define _NONSTD_SOURCE when only UNIX conformance is available."
#    endif /* _NONSTD_SOURCE */
#    define __DARWIN_UNIX03	1
#  elif defined(_DARWIN_C_SOURCE) || defined(_XOPEN_SOURCE) || defined(_POSIX_C_SOURCE)
#    if defined(_NONSTD_SOURCE)
#      error "Can't define both _NONSTD_SOURCE and any of _DARWIN_C_SOURCE, _XOPEN_SOURCE or _POSIX_C_SOURCE."
#    endif /* _NONSTD_SOURCE */
#    define __DARWIN_UNIX03	1
#  elif defined(_NONSTD_SOURCE)
#    define __DARWIN_UNIX03	0
#  else /* default */
#    if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && ((__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__-0) < 1050)
#      define __DARWIN_UNIX03	0
#    else /* __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1050 */
#      define __DARWIN_UNIX03	1
#    endif /* __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1050 */
#  endif /* _DARWIN_C_SOURCE || _XOPEN_SOURCE || _POSIX_C_SOURCE || __LP64__ */
#endif /* !__DARWIN_UNIX03 */

#if !defined(__DARWIN_64_BIT_INO_T)
#  if defined(KERNEL)
#    define __DARWIN_64_BIT_INO_T 0
#  elif defined(_DARWIN_USE_64_BIT_INODE)
#    if defined(_DARWIN_NO_64_BIT_INODE)
#      error "Can't define both _DARWIN_USE_64_BIT_INODE and _DARWIN_NO_64_BIT_INODE."
#    endif /* _DARWIN_NO_64_BIT_INODE */
#    define __DARWIN_64_BIT_INO_T 1
#  elif defined(_DARWIN_NO_64_BIT_INODE)
#    if __DARWIN_ONLY_64_BIT_INO_T
#      error "Can't define _DARWIN_NO_64_BIT_INODE when only 64-bit inodes are available."
#    endif /* __DARWIN_ONLY_64_BIT_INO_T */
#    define __DARWIN_64_BIT_INO_T 0
#  else /* default */
#    if __DARWIN_ONLY_64_BIT_INO_T
#      define __DARWIN_64_BIT_INO_T 1
#    elif defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && ((__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__-0) < 1060) || __DARWIN_UNIX03 == 0
#      define __DARWIN_64_BIT_INO_T 0
#    else /* default */
#      define __DARWIN_64_BIT_INO_T 1
#    endif /* __DARWIN_ONLY_64_BIT_INO_T */
#  endif
#endif /* !__DARWIN_64_BIT_INO_T */

#if !defined(__DARWIN_VERS_1050)
#  if defined(KERNEL)
#    define __DARWIN_VERS_1050 0
#  elif __DARWIN_ONLY_VERS_1050
#    define __DARWIN_VERS_1050 1
#  elif defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && ((__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__-0) < 1050) || __DARWIN_UNIX03 == 0
#    define __DARWIN_VERS_1050 0
#  else /* default */
#    define __DARWIN_VERS_1050 1
#  endif
#endif /* !__DARWIN_VERS_1050 */

#if !defined(__DARWIN_NON_CANCELABLE)
#  if defined(KERNEL)
#    define __DARWIN_NON_CANCELABLE 0
#  else /* default */
#    define __DARWIN_NON_CANCELABLE 0
#  endif
#endif /* !__DARWIN_NON_CANCELABLE */

/*
 * symbol suffixes used for symbol versioning
 */
#if __DARWIN_UNIX03
#  if __DARWIN_ONLY_UNIX_CONFORMANCE
#    define __DARWIN_SUF_UNIX03		/* nothing */
#  else /* !__DARWIN_ONLY_UNIX_CONFORMANCE */
#    define __DARWIN_SUF_UNIX03		"$UNIX2003"
#  endif /* __DARWIN_ONLY_UNIX_CONFORMANCE */

#  if __DARWIN_64_BIT_INO_T
#    if __DARWIN_ONLY_64_BIT_INO_T
#      define __DARWIN_SUF_64_BIT_INO_T	/* nothing */
#    else /* !__DARWIN_ONLY_64_BIT_INO_T */
#      define __DARWIN_SUF_64_BIT_INO_T	"$INODE64"
#    endif /* __DARWIN_ONLY_64_BIT_INO_T */
#  else /* !__DARWIN_64_BIT_INO_T */
#    define __DARWIN_SUF_64_BIT_INO_T	/* nothing */
#  endif /* __DARWIN_64_BIT_INO_T */

#  if __DARWIN_VERS_1050
#    if __DARWIN_ONLY_VERS_1050
#      define __DARWIN_SUF_1050		/* nothing */
#    else /* !__DARWIN_ONLY_VERS_1050 */
#      define __DARWIN_SUF_1050		"$1050"
#    endif /* __DARWIN_ONLY_VERS_1050 */
#  else /* !__DARWIN_VERS_1050 */
#    define __DARWIN_SUF_1050		/* nothing */
#  endif /* __DARWIN_VERS_1050 */

#  if __DARWIN_NON_CANCELABLE
#    define __DARWIN_SUF_NON_CANCELABLE	"$NOCANCEL"
#  else /* !__DARWIN_NON_CANCELABLE */
#    define __DARWIN_SUF_NON_CANCELABLE	/* nothing */
#  endif /* __DARWIN_NON_CANCELABLE */

#else /* !__DARWIN_UNIX03 */
#  define __DARWIN_SUF_UNIX03		/* nothing */
#  define __DARWIN_SUF_64_BIT_INO_T	/* nothing */
#  define __DARWIN_SUF_NON_CANCELABLE	/* nothing */
#  define __DARWIN_SUF_1050		/* nothing */
#endif /* __DARWIN_UNIX03 */

#define __DARWIN_SUF_EXTSN		"$DARWIN_EXTSN"

/*
 * symbol versioning macros
 */
#define __DARWIN_ALIAS(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_UNIX03)
#define __DARWIN_ALIAS_C(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_NON_CANCELABLE __DARWIN_SUF_UNIX03)
#define __DARWIN_ALIAS_I(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_64_BIT_INO_T __DARWIN_SUF_UNIX03)
#define __DARWIN_INODE64(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_64_BIT_INO_T)

#define __DARWIN_1050(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_1050)
#define __DARWIN_1050ALIAS(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_1050 __DARWIN_SUF_UNIX03)
#define __DARWIN_1050ALIAS_C(sym)	__asm("_" __STRING(sym) __DARWIN_SUF_1050 __DARWIN_SUF_NON_CANCELABLE __DARWIN_SUF_UNIX03)
#define __DARWIN_1050ALIAS_I(sym)	__asm("_" __STRING(sym) __DARWIN_SUF_1050 __DARWIN_SUF_64_BIT_INO_T __DARWIN_SUF_UNIX03)
#define __DARWIN_1050INODE64(sym)	__asm("_" __STRING(sym) __DARWIN_SUF_1050 __DARWIN_SUF_64_BIT_INO_T)

#define __DARWIN_EXTSN(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_EXTSN)
#define __DARWIN_EXTSN_C(sym)		__asm("_" __STRING(sym) __DARWIN_SUF_EXTSN __DARWIN_SUF_NON_CANCELABLE)

/*
 * symbol release macros
 */
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && ((__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__-0) < 1060)
#undef __DARWIN_10_6_AND_LATER
#define __DARWIN_10_6_AND_LATER_ALIAS(x)	/* nothing */
#else /* 10.6 and beyond */
#define __DARWIN_10_6_AND_LATER
#define __DARWIN_10_6_AND_LATER_ALIAS(x)	x
#endif


/*
 * POSIX.1 requires that the macros we test be defined before any standard
 * header file is included.  This permits us to convert values for feature
 * testing, as necessary, using only _POSIX_C_SOURCE.
 *
 * Here's a quick run-down of the versions:
 *  defined(_POSIX_SOURCE)		1003.1-1988
 *  _POSIX_C_SOURCE == 1L		1003.1-1990
 *  _POSIX_C_SOURCE == 2L		1003.2-1992 C Language Binding Option
 *  _POSIX_C_SOURCE == 199309L		1003.1b-1993
 *  _POSIX_C_SOURCE == 199506L		1003.1c-1995, 1003.1i-1995,
 *					and the omnibus ISO/IEC 9945-1: 1996
 *  _POSIX_C_SOURCE == 200112L		1003.1-2001
 *
 * In addition, the X/Open Portability Guide, which is now the Single UNIX
 * Specification, defines a feature-test macro which indicates the version of
 * that specification, and which subsumes _POSIX_C_SOURCE.
 */

/* Deal with IEEE Std. 1003.1-1990, in which _POSIX_C_SOURCE == 1L. */
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE == 1L
#undef _POSIX_C_SOURCE
#define	_POSIX_C_SOURCE		199009L
#endif

/* Deal with IEEE Std. 1003.2-1992, in which _POSIX_C_SOURCE == 2L. */
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE == 2L
#undef _POSIX_C_SOURCE
#define	_POSIX_C_SOURCE		199209L
#endif

/* Deal with various X/Open Portability Guides and Single UNIX Spec. */
#ifdef _XOPEN_SOURCE
#if _XOPEN_SOURCE - 0L >= 600L
#undef _POSIX_C_SOURCE
#define	_POSIX_C_SOURCE		200112L
#elif _XOPEN_SOURCE - 0L >= 500L
#undef _POSIX_C_SOURCE
#define	_POSIX_C_SOURCE		199506L
#endif
#endif

/*
 * Deal with all versions of POSIX.  The ordering relative to the tests above is
 * important.
 */
#if defined(_POSIX_SOURCE) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE         198808L
#endif

/*
 * long long is not supported in c89 (__STRICT_ANSI__), but g++ -ansi and
 * c99 still want long longs.  While not perfect, we allow long longs for
 * g++.
 */
#define	__DARWIN_NO_LONG_LONG	(defined(__STRICT_ANSI__) \
				&& (__STDC_VERSION__-0 < 199901L) \
				&& !defined(__GNUG__))

/*
 * Long double compatibility macro allow selecting variant symbols based
 * on the old (compatible) 64-bit long doubles, or the new 128-bit
 * long doubles.  This applies only to ppc; i386 already has long double
 * support, while ppc64 doesn't have any backwards history.
 */
#if   defined(__ppc__)
#  if defined(__LDBL_MANT_DIG__) && defined(__DBL_MANT_DIG__) && \
	__LDBL_MANT_DIG__ > __DBL_MANT_DIG__
#    if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__-0 < 1040
#      define	__DARWIN_LDBL_COMPAT(x)	__asm("_" __STRING(x) "$LDBLStub")
#    else
#      define	__DARWIN_LDBL_COMPAT(x)	__asm("_" __STRING(x) "$LDBL128")
#    endif
#    define	__DARWIN_LDBL_COMPAT2(x) __asm("_" __STRING(x) "$LDBL128")
#    define	__DARWIN_LONG_DOUBLE_IS_DOUBLE	0
#  else
#   define	__DARWIN_LDBL_COMPAT(x) /* nothing */
#   define	__DARWIN_LDBL_COMPAT2(x) /* nothing */
#   define	__DARWIN_LONG_DOUBLE_IS_DOUBLE	1
#  endif
#elif defined(__i386__) || defined(__ppc64__) || defined(__x86_64__)
#  define	__DARWIN_LDBL_COMPAT(x)	/* nothing */
#  define	__DARWIN_LDBL_COMPAT2(x) /* nothing */
#  define	__DARWIN_LONG_DOUBLE_IS_DOUBLE	0
#else
#  error Unknown architecture
#endif

/*
 * Deprecation macro
 */
#if __GNUC__ >= 3
#define __deprecated __attribute__((deprecated))
#else
#define __deprecated /* nothing */
#endif

/*****************************************
 *  Public darwin-specific feature macros
 *****************************************/

/*
 * _DARWIN_FEATURE_64_BIT_INODE indicates that the ino_t type is 64-bit, and
 * structures modified for 64-bit inodes (like struct stat) will be used.
 */
#if __DARWIN_64_BIT_INO_T
#define _DARWIN_FEATURE_64_BIT_INODE		1
#endif

/*
 * _DARWIN_FEATURE_LONG_DOUBLE_IS_DOUBLE indicates when the long double type
 * is the same as the double type (ppc and arm only)
 */
#if __DARWIN_LONG_DOUBLE_IS_DOUBLE
#define _DARWIN_FEATURE_LONG_DOUBLE_IS_DOUBLE	1
#endif

/*
 * _DARWIN_FEATURE_64_ONLY_BIT_INODE indicates that the ino_t type may only
 * be 64-bit; there is no support for 32-bit ino_t when this macro is defined
 * (and non-zero).  There is no struct stat64 either, as the regular
 * struct stat will already be the 64-bit version.
 */
#if __DARWIN_ONLY_64_BIT_INO_T
#define _DARWIN_FEATURE_ONLY_64_BIT_INODE	1
#endif

/*
 * _DARWIN_FEATURE_ONLY_VERS_1050 indicates that only those APIs updated
 * in 10.5 exists; no pre-10.5 variants are available.
 */
#if __DARWIN_ONLY_VERS_1050
#define _DARWIN_FEATURE_ONLY_VERS_1050		1
#endif

/*
 * _DARWIN_FEATURE_ONLY_UNIX_CONFORMANCE indicates only UNIX conforming API
 * are available (the legacy BSD APIs are not available)
 */
#if __DARWIN_ONLY_UNIX_CONFORMANCE
#define _DARWIN_FEATURE_ONLY_UNIX_CONFORMANCE	1
#endif

/*
 * _DARWIN_FEATURE_UNIX_CONFORMANCE indicates whether UNIX conformance is on,
 * and specifies the conformance level (3 is SUSv3)
 */
#if __DARWIN_UNIX03
#define _DARWIN_FEATURE_UNIX_CONFORMANCE	3
#endif

/* 
 * This macro casts away the qualifier from the variable
 *
 * Note: use at your own risk, removing qualifiers can result in
 * catastrophic run-time failures.
 */
#ifndef __CAST_AWAY_QUALIFIER
#define __CAST_AWAY_QUALIFIER(variable, qualifier, type)  (type) ((char *)0 + ((qualifier char *)(variable) - (qualifier char *)0) ) 
#endif

#endif /* !_CDEFS_H_ */
