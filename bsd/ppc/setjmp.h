/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
	unsigned long vmask __attribute__((aligned(8))); /* vector mask register */
	unsigned long vreg[32 * 4] __attribute__((aligned(16)));
		/* 32 128-bit vector registers */
};

/*
 *	_JBLEN is number of ints required to save the following:
 *	r1, r2, r13-r31, lr, cr, ctr, xer, sig  == 26 ints
 *	fr14 -  fr31 = 18 doubles = 36 ints
 *	vmask, 32 vector registers = 129 ints
 *	2 ints to get all the elements aligned 
 */

#define _JBLEN (26 + 36 + 129 + 1)

#if defined(KERNEL)
typedef struct sigcontext jmp_buf[1];
typedef struct __sigjmp_buf {
		int __storage[_JBLEN + 1] __attribute__((aligned(8)));
		} sigjmp_buf[1];
#else
typedef int jmp_buf[_JBLEN];
typedef int sigjmp_buf[_JBLEN + 1];
#endif

__BEGIN_DECLS
extern int setjmp __P((jmp_buf env));
extern void longjmp __P((jmp_buf env, int val));

#ifndef _ANSI_SOURCE
int sigsetjmp __P((sigjmp_buf env, int val));
void siglongjmp __P((sigjmp_buf env, int val));
#endif /* _ANSI_SOURCE  */

#if !defined(_ANSI_SOURCE) && !defined(_POSIX_SOURCE)
int	_setjmp __P((jmp_buf env));
void	_longjmp __P((jmp_buf, int val));
void	longjmperror __P((void));
#endif /* neither ANSI nor POSIX */
__END_DECLS

#endif /* !_BSD_PPC_SETJMP_H_ */
