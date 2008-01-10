/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_UCONTEXT_H_
#define _I386_UCONTEXT_H_


#include <sys/appleapiopts.h>
#include <mach/thread_status.h>

#ifndef _POSIX_C_SOURCE
struct mcontext
#else /* _POSIX_C_SOURCE */
struct __darwin_mcontext
#endif /* _POSIX_C_SOURCE */
{
#if __LP64__
	x86_exception_state64_t	es;
	x86_thread_state64_t 	ss;	
	x86_float_state64_t	fs;
#else
	x86_exception_state32_t	es;
	x86_thread_state32_t 	ss;	
	x86_float_state32_t	fs;
#endif
};

#ifndef _POSIX_C_SOURCE
#if __LP64__
#define I386_MCONTEXT_SIZE	(x86_THREAD_STATE64_COUNT + x86_FLOAT_STATE64_COUNT + x86_EXCEPTION_STATE64_COUNT) * sizeof(int)
#else
#define I386_MCONTEXT_SIZE	(x86_THREAD_STATE32_COUNT + x86_FLOAT_STATE32_COUNT + x86_EXCEPTION_STATE32_COUNT) * sizeof(int)
#endif
#endif /* _POSIX_C_SOURCE */

#ifndef _MCONTEXT_T
#define _MCONTEXT_T
typedef __darwin_mcontext_t	mcontext_t;
#endif


#ifdef XNU_KERNEL_PRIVATE
struct mcontext64 {
	x86_exception_state64_t	es;
	x86_thread_state64_t 	ss;	
	x86_float_state64_t	fs;
};

struct mcontext32 {
	x86_exception_state32_t	es;
	x86_thread_state32_t 	ss;	
	x86_float_state32_t	fs;
};
#endif


#endif /* _I386_UCONTEXT_H_ */
