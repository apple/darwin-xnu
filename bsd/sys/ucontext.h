/*
 * Copyright (c) 2002-2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_UCONTEXT_H_
#define _SYS_UCONTEXT_H_

#include <sys/cdefs.h>
#include <sys/_types.h>
#include <machine/ucontext.h>

#ifndef _SIGSET_T
#define _SIGSET_T
typedef __darwin_sigset_t	sigset_t;
#endif

#ifndef _STACK_T
#define _STACK_T
typedef __darwin_stack_t	stack_t;
#endif

#ifndef _UCONTEXT_T
#define _UCONTEXT_T
#ifndef _POSIX_C_SOURCE
typedef struct ucontext 	ucontext_t;
#else /* _POSIX_C_SOURCE */
typedef struct __darwin_ucontext ucontext_t;
#endif /* _POSIX_C_SOURCE */
#endif

#ifndef _POSIX_C_SOURCE
#ifndef _UCONTEXT64_T
#define _UCONTEXT64_T
typedef struct ucontext64	ucontext64_t;
#endif
#endif /* _POSIX_C_SOURCE */

#ifdef KERNEL
#include <machine/types.h>	/* user_addr_t, user_size_t */

#if __DARWIN_ALIGN_NATURAL
#pragma options align=natural
#endif

/* kernel representation of struct ucontext64 for 64 bit processes */
struct user_ucontext64 {
	int				uc_onstack;
	sigset_t			uc_sigmask;	/* signal mask */
	struct user_sigaltstack 	uc_stack;	/* stack */
	user_addr_t			uc_link;	/* ucontext pointer */
	user_size_t			uc_mcsize;	/* mcontext size */
	user_addr_t			uc_mcontext64;	/* machine context */
};

#if __DARWIN_ALIGN_NATURAL
#pragma options align=reset
#endif

typedef struct user_ucontext64 user_ucontext64_t;
#endif	/* KERNEL */

#endif /* _SYS_UCONTEXT_H_ */
