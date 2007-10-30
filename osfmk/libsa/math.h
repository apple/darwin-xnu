/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:51  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:35  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1997/01/31  15:46:32  emcmanus
 * 	Merged with nmk22b1_shared.
 * 	[1997/01/30  16:57:28  emcmanus]
 *
 * Revision 1.1.2.4  1997/01/03  10:11:22  yp
 * 	isnan() prototype for JDK.
 * 	[97/01/03            yp]
 * 
 * Revision 1.1.2.3  1996/11/29  14:33:24  yp
 * 	Added more prototypes.
 * 	[96/11/29            yp]
 * 
 * Revision 1.1.2.2  1996/10/10  13:56:16  yp
 * 	Submitted again (ODE problems).
 * 	[96/10/10            yp]
 * 
 * Revision 1.1.2.1  1996/10/10  09:16:46  yp
 * 	Created.
 * 	[96/10/10            yp]
 * 
 * $EndLog$
 */

#ifndef	_MATH_H_
#define	_MATH_H_ 1

double acos (double);
double acosh (double);
double asin (double);
double asinh (double);
double atan (double);
double atanh (double);
double atan2 (double, double);
double cbrt (double);
double ceil (double);
double copysign (double, double);
double cos (double);
double cosh (double);
double drem (double);
double exp (double);
double expm1 (double);
double fabs (double);
int    finite (double);
double floor (double);
double fmod (double, double);
double frexp (double, int *);
int    ilogb (double);
int    isnan(double);
double ldexp (double, int);
double log (double);
double log10 (double);
double log1p (double);
double logb (double);
double modf (double, double *);
double nextafter (double, double);
double pow (double, double);
double remainder (double, double);
double rint (double);
double scalb (double, double);
double sin (double);
double sinh (double);
double sqrt (double);
double tan (double);
double tanh (double);

#include <machine/math.h>

#endif	/* _MATH_H_ */
