/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef _MACHINE_ENDIAN_H_
#define _MACHINE_ENDIAN_H_

/*
 * Definitions for byte order,
 * according to byte significance from low address to high.
 */
#define	LITTLE_ENDIAN	1234	/* least-significant byte first (vax) */
#define	BIG_ENDIAN	4321	/* most-significant byte first (IBM, net) */
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in long (pdp) */

#define	BYTE_ORDER	LITTLE_ENDIAN	/* byte order on i386 */
#define ENDIAN		LITTLE

/*
 * Macros for network/external number representation conversion.
 * Use GNUC support to inline the byteswappers.
 */

#if !defined(ntohs)
unsigned short	ntohs(unsigned short);
extern __inline__
unsigned short
ntohs(unsigned short w_int)
{
	register unsigned short w = w_int;
	__asm__ volatile("xchgb	%h1,%b1" : "=q" (w) : "0" (w));
	return (w);	/* zero-extend for compat */
}
#endif

#if !defined(htons)
unsigned short	htons(unsigned short);
#define	htons	ntohs
#endif

#if !defined(ntohl)
unsigned long	ntohl(unsigned long);
extern __inline__
unsigned long
ntohl(register unsigned long value)
{
	register unsigned long l = value;
	__asm__ volatile("bswap %0" : "=r" (l) : "0" (l));
	return l;
}
#endif

#if !defined(htonl)
unsigned long	htonl(unsigned long);
#define htonl	ntohl
#endif

#define NTOHL(x)	(x) = ntohl((unsigned long)x)
#define NTOHS(x)	(x) = ntohs((unsigned short)x)
#define HTONL(x)	(x) = htonl((unsigned long)x)
#define HTONS(x)	(x) = htons((unsigned short)x)

#endif
