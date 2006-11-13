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
/* Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 *	File:	ppc/setjmp.h
 *
 *	Declaration of setjmp routines and data structures.
 */
#ifndef _BSD_PPC_SETJMP_H_
#define _BSD_PPC_SETJMP_H_

#include <sys/cdefs.h>
#include <machine/signal.h>

struct _jmp_buf {
	struct sigcontext	sigcontext; /* kernel state preserved by set/longjmp */
	unsigned int vmask __attribute__((aligned(8))); /* vector mask register */
	unsigned int vreg[32 * 4] __attribute__((aligned(16)));
		/* 32 128-bit vector registers */
};

/*
 *	_JBLEN is number of ints required to save the following:
 *	r1, r2, r13-r31, lr, cr, ctr, xer, sig  == 26 register_t sized
 *	fr14 -  fr31 = 18 doubles
 *	vmask, 32 vector registers = 129 ints
 *	2 ints to get all the elements aligned 
 *
 *	register_t is 2 ints for ppc64 threads
 */
#define _JBLEN64	(26*2 + 18*2 + 129 + 1)
#define _JBLEN32	(26 + 18*2 + 129 + 1)
#define _JBLEN_MAX	_JBLEN64

/*
 * Locally scoped sizes
 */
#if defined(__ppc64__)
#define _JBLEN _JBLEN64
#else
#define _JBLEN _JBLEN32
#endif

#if defined(KERNEL)
typedef struct sigcontext32 jmp_buf32[1];
typedef struct __sigjmp_buf32 {
		int __storage[_JBLEN32 + 1] __attribute__((aligned(8)));
		} sigjmp_buf32[1];

typedef struct sigcontext64 jmp_buf64[1];
typedef struct __sigjmp_buf64 {
		int __storage[_JBLEN64 + 1] __attribute__((aligned(8)));
		} sigjmp_buf64[1];

/*
 * JMM - have to decide how the kernel will deal with this.
 * For now, hard-code the 32-bit types.
 */
typedef struct sigcontext32 jmp_buf[1];
typedef struct __sigjmp_buf32 sigjmp_buf[1];

#else
typedef int jmp_buf[_JBLEN];
typedef int sigjmp_buf[_JBLEN + 1];
#endif

__BEGIN_DECLS
extern int setjmp(jmp_buf env);
extern void longjmp(jmp_buf env, int val);

#ifndef _ANSI_SOURCE
int	_setjmp(jmp_buf env);
void	_longjmp(jmp_buf, int val);
int sigsetjmp(sigjmp_buf env, int val);
void siglongjmp(sigjmp_buf env, int val);
#endif /* _ANSI_SOURCE  */

#if !defined(_ANSI_SOURCE) && !defined(_POSIX_C_SOURCE)
void	longjmperror(void);
#endif /* neither ANSI nor POSIX */
__END_DECLS

#endif /* !_BSD_PPC_SETJMP_H_ */
