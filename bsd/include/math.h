/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 by NeXT Computer, Inc. All rights reserved. */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 */

#ifndef _MATH_H_
#define _MATH_H_

/*
 * ANSI/POSIX
 */
#define	HUGE_VAL	1e500			/* IEEE: positive infinity */

/*
 * XOPEN/SVID
 */
#if !defined(_ANSI_SOURCE) && !defined(_POSIX_SOURCE)
#define	M_E		2.7182818284590452354	/* e */
#define	M_LOG2E		1.4426950408889634074	/* log 2e */
#define	M_LOG10E	0.43429448190325182765	/* log 10e */
#define	M_LN2		0.69314718055994530942	/* log e2 */
#define	M_LN10		2.30258509299404568402	/* log e10 */
#define	M_PI		3.14159265358979323846	/* pi */
#define	M_PI_2		1.57079632679489661923	/* pi/2 */
#define	M_PI_4		0.78539816339744830962	/* pi/4 */
#define	M_1_PI		0.31830988618379067154	/* 1/pi */
#define	M_2_PI		0.63661977236758134308	/* 2/pi */
#define	M_2_SQRTPI	1.12837916709551257390	/* 2/sqrt(pi) */
#define	M_SQRT2		1.41421356237309504880	/* sqrt(2) */
#define	M_SQRT1_2	0.70710678118654752440	/* 1/sqrt(2) */

#define	MAXFLOAT	((float)3.40282346638528860e+38)
extern int signgam;

#if !defined(_XOPEN_SOURCE)
enum fdversion {fdlibm_ieee = -1, fdlibm_svid, fdlibm_xopen, fdlibm_posix};

#define _LIB_VERSION_TYPE enum fdversion
#define _LIB_VERSION _fdlib_version  

/* if global variable _LIB_VERSION is not desirable, one may 
 * change the following to be a constant by: 
 *	#define _LIB_VERSION_TYPE const enum version
 * In that case, after one initializes the value _LIB_VERSION (see
 * s_lib_version.c) during compile time, it cannot be modified
 * in the middle of a program
 */ 
extern  _LIB_VERSION_TYPE  _LIB_VERSION;

#define _IEEE_  fdlibm_ieee
#define _SVID_  fdlibm_svid
#define _XOPEN_ fdlibm_xopen
#define _POSIX_ fdlibm_posix

#if !defined(__cplusplus)
struct exception {
	int type;
	char *name;
	double arg1;
	double arg2;
	double retval;
};
#endif

#define	HUGE		MAXFLOAT

/* 
 * set X_TLOSS = pi*2**52, which is possibly defined in <values.h>
 * (one may replace the following line by "#include <values.h>")
 */

#define X_TLOSS		1.41484755040568800000e+16 

#define	DOMAIN		1
#define	SING		2
#define	OVERFLOW	3
#define	UNDERFLOW	4
#define	TLOSS		5
#define	PLOSS		6

#endif /* !_XOPEN_SOURCE */
#endif /* !_ANSI_SOURCE && !_POSIX_SOURCE */


#include <sys/cdefs.h>
__BEGIN_DECLS
/*
 * ANSI/POSIX
 */
extern __pure double acos __P((double));
extern __pure double asin __P((double));
extern __pure double atan __P((double));
extern __pure double atan2 __P((double, double));
extern __pure double cos __P((double));
extern __pure double sin __P((double));
extern __pure double tan __P((double));

extern __pure double cosh __P((double));
extern __pure double sinh __P((double));
extern __pure double tanh __P((double));

extern __pure double exp __P((double));
extern double frexp __P((double, int *));
extern __pure double ldexp __P((double, int));
extern __pure double log __P((double));
extern __pure double log10 __P((double));
extern double modf __P((double, double *));

extern __pure double pow __P((double, double));
extern __pure double sqrt __P((double));

extern __pure double ceil __P((double));
extern __pure double fabs __P((double));
extern __pure double floor __P((double));
extern __pure double fmod __P((double, double));

#if !defined(_ANSI_SOURCE) && !defined(_POSIX_SOURCE)
extern __pure double erf __P((double));
extern __pure double erfc __P((double));
extern double gamma __P((double));
extern __pure double hypot __P((double, double));
extern __pure int isinf __P((double));
extern __pure int isnan __P((double));
extern __pure  int finite __P((double));
extern __pure double j0 __P((double));
extern __pure double j1 __P((double));
extern __pure double jn __P((int, double));
extern double lgamma __P((double));
extern __pure double y0 __P((double));
extern __pure double y1 __P((double));
extern __pure double yn __P((int, double));

#if !defined(_XOPEN_SOURCE)
extern __pure double acosh __P((double));
extern __pure double asinh __P((double));
extern __pure double atanh __P((double));
extern __pure double cbrt __P((double));
extern __pure double logb __P((double));
extern __pure double nextafter __P((double, double));
extern __pure double remainder __P((double, double));
extern __pure double scalb __P((double, int));

#ifndef __cplusplus
extern int matherr __P((struct exception *));
#endif

/*
 * IEEE Test Vector
 */
extern __pure double significand __P((double));

/*
 * Functions callable from C, intended to support IEEE arithmetic.
 */
extern __pure double copysign __P((double, double));
extern __pure int ilogb __P((double));
extern __pure double rint __P((double));
extern __pure double scalbn __P((double, int));

/*
 * BSD math library entry points
 */
extern double cabs();
extern __pure double drem __P((double, double));
extern __pure double expm1 __P((double));
extern __pure double log1p __P((double));

/*
 * Reentrant version of gamma & lgamma; passes signgam back by reference
 * as the second argument; user must allocate space for signgam.
 */
#ifdef _REENTRANT
extern double gamma_r __P((double, int *));
extern double lgamma_r __P((double, int *));
#endif /* _REENTRANT */
#endif /* !_XOPEN_SOURCE */
#endif /* !_ANSI_SOURCE && !_POSIX_SOURCE */
__END_DECLS

#endif /* _MATH_H_ */
