/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
size_t	utf8_encodelen __P((const u_int16_t *, size_t, u_int16_t, int));

int	utf8_encodestr __P((const u_int16_t *, size_t, u_int8_t *, size_t *,
		size_t, u_int16_t, int));

int	utf8_decodestr __P((const u_int8_t *, size_t, u_int16_t *,size_t *,
		size_t, u_int16_t, int));
__END_DECLS

#endif /* __APPLE_API_UNSTABLE */
#endif /* KERNEL */

#endif /* !_SYS_UTFCONV_H_ */
