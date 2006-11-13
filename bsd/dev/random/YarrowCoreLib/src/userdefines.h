/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

/*
	userdefines.h

	Header file that contains the major user-defineable quantities for the Counterpane PRNG.
*/
#ifndef __YARROW_USER_DEFINES_H__
#define __YARROW_USER_DEFINES_H__

/* User-alterable define statements */
#define STRICT				/* Define to force strict type checking */
#define K 0					/* How many sources should we ignore when calculating total entropy? */
#define THRESHOLD 100		/* Minimum amount of entropy for a reseed */
#define BACKTRACKLIMIT 500	/* Number of outputed bytes after which to generate a new state */
#define COMPRESSION_ON		/* Define this variable to add on-the-fly compression (recommended) */
							/* for user sources */
#if		!defined(macintosh) && !defined(__APPLE__)
#define WIN_95				/* Choose an OS: WIN_95, WIN_NT */
#endif

/* Setup Microsoft flag for NT4.0 */
#ifdef WIN_NT
#define _WIN32_WINNT 0x0400
#endif

#endif	/* __YARROW_USER_DEFINES_H__ */
