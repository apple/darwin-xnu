/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_UTFCONV_H_
#define	_SYS_UTFCONV_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h> 

#ifdef KERNEL
#ifdef __APPLE_API_UNSTABLE
/*
 * UTF-8 encode/decode flags
 */
#define	UTF_REVERSE_ENDIAN	0x01	/* reverse UCS-2 byte order */
#define UTF_NO_NULL_TERM	0x02	/* do not add null termination */
#define	UTF_DECOMPOSED		0x04	/* generate fully decomposed UCS-2 */
#define	UTF_PRECOMPOSED		0x08	/* generate precomposed UCS-2 */

__BEGIN_DECLS
size_t	utf8_encodelen(const u_int16_t *, size_t, u_int16_t, int);

int	utf8_encodestr(const u_int16_t *, size_t, u_int8_t *, size_t *,
		size_t, u_int16_t, int);

int	utf8_decodestr(const u_int8_t *, size_t, u_int16_t *,size_t *,
		size_t, u_int16_t, int);

int	utf8_validatestr(const u_int8_t*, size_t);

__END_DECLS

#endif /* __APPLE_API_UNSTABLE */
#endif /* KERNEL */

#endif /* !_SYS_UTFCONV_H_ */
