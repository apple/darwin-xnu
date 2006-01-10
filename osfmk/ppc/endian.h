/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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

#ifdef __BIG_ENDIAN__			/* Predefined by compiler */
#define	BYTE_ORDER	BIG_ENDIAN	/* byte order we use on ppc */
#define ENDIAN		BIG
#else
#error code has not been ported to little endian targets yet
#endif

/*
 * Macros for network/external number representation conversion.
 */
#if BYTE_ORDER == BIG_ENDIAN && !defined(lint)
#define	ntohl(x)	(x)
#define	ntohs(x)	(x)
#define	htonl(x)	(x)
#define	htons(x)	(x)

static __inline__ unsigned int byte_reverse_word(unsigned int word);
static __inline__ unsigned int byte_reverse_word(unsigned int word) {
	unsigned int result;
	__asm__ volatile("lwbrx	%0, 0, %1" : "=r" (result) : "r" (&word));
	return result;
}

/* The above function is commutative, so we can use it for
 * translations in both directions (to/from little endianness)
 * Note that htolx and ltohx are probably identical, they are
 * included for completeness.
 */
#define htoll(x)  byte_reverse_word(x)
#define htols(x)  (byte_reverse_word(x) >> 16)
#define ltohl(x)  htoll(x)
#define ltohs(x)  htols(x)

#define htobl(x) (x)
#define htobs(x) (x)
#define btohl(x) (x)
#define btohs(x) (x)

#else
unsigned short	ntohs(), htons();
unsigned long	ntohl(), htonl();
#endif

/* This defines the order of elements in a bitfield,
 * it is principally used by the SCSI subsystem in
 * the definitions of mapped registers
 */
#define BYTE_MSF 1

#endif /* _MACHINE_ENDIAN_H_ */
