/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)libkern.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _LIBKERN_LIBKERN_H_
#define _LIBKERN_LIBKERN_H_

#include <sys/appleapiopts.h>
#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <mach/vm_param.h>

#ifdef __APPLE_API_OBSOLETE
/* BCD conversions. */
extern u_char const	bcd2bin_data[];
extern u_char const	bin2bcd_data[];

#define	bcd2bin(bcd)	(bcd2bin_data[bcd])
#define	bin2bcd(bin)	(bin2bcd_data[bin])
#endif /* __APPLE_API_OBSOLETE */

#ifdef __APPLE_API_PRIVATE
extern char const	hex2ascii_data[];

#define	hex2ascii(hex)	(hex2ascii_data[hex])
#endif /* __APPLE_API_PRIVATE */

__BEGIN_DECLS
static inline int
imax(int a, int b)
{
	return (a > b ? a : b);
}
static inline int
imin(int a, int b)
{
	return (a < b ? a : b);
}
static inline long
lmax(long a, long b)
{
	return (a > b ? a : b);
}
static inline long
lmin(long a, long b)
{
	return (a < b ? a : b);
}
static inline u_int
max(u_int a, u_int b)
{
	return (a > b ? a : b);
}
static inline u_int
min(u_int a, u_int b)
{
	return (a < b ? a : b);
}
static inline u_long
ulmax(u_long a, u_long b)
{
	return (a > b ? a : b);
}
static inline u_long
ulmin(u_long a, u_long b)
{
	return (a < b ? a : b);
}

/* Prototypes for non-quad routines. */
extern int	ffs(int);
extern int	locc(int, char *, u_int);
extern u_long	random(void);
extern char	*rindex(const char *, int);
extern int	scanc(u_int, u_char *, const u_char *, int);
extern int	skpc(int, int, char *);
extern long	strtol(const char*, char **, int);
extern u_long	strtoul(const char *, char **, int);
extern quad_t	strtoq(const char *, char **, int);
extern u_quad_t strtouq(const char *, char **, int);

int	snprintf(char *, size_t, const char *, ...);
int	sprintf(char *bufp, const char *, ...);
int	sscanf(const char *, char const *, ...);
void printf(const char *, ...);

uint32_t	crc32(uint32_t crc, const void *bufp, size_t len);

int	copystr(const void *kfaddr, void *kdaddr, size_t len, size_t *done);
int	copyinstr(const user_addr_t uaddr, void *kaddr, size_t len, size_t *done);
int	copyoutstr(const void *kaddr, user_addr_t udaddr, size_t len, size_t *done);
int	copyin(const user_addr_t uaddr, void *kaddr, size_t len);
int	copyout(const void *kaddr, user_addr_t udaddr, size_t len);

int vsscanf(const char *, char const *, __darwin_va_list);
extern int	vsnprintf(char *, size_t, const char *, __darwin_va_list);
extern int	vsprintf(char *bufp, const char *, __darwin_va_list); 

extern void invalidate_icache(vm_offset_t, unsigned, int);
extern void flush_dcache(vm_offset_t, unsigned, int);
extern void invalidate_icache64(addr64_t, unsigned, int);
extern void flush_dcache64(addr64_t, unsigned, int);

__END_DECLS

#endif /* _LIBKERN_LIBKERN_H_ */
