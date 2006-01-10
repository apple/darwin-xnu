/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_UCONTEXT_H_
#define _I386_UCONTEXT_H_


#include <sys/appleapiopts.h>
#include <mach/thread_status.h>

#ifdef __APPLE_API_UNSTABLE
/* WARNING: THIS WILL CHANGE;  DO NOT COUNT ON THIS */
/* Needs to be finalized as to what it should contain */
#ifndef _POSIX_C_SOURCE
struct mcontext
#else /* _POSIX_C_SOURCE */
struct __darwin_mcontext
#endif /* _POSIX_C_SOURCE */
{
	struct sigcontext sc;
};

#ifndef _POSIX_C_SOURCE
#define I386_MCONTEXT_SIZE	sizeof(struct mcontext)	
#endif /* _POSIX_C_SOURCE */

#ifndef _MCONTEXT_T
#define _MCONTEXT_T
typedef __darwin_mcontext_t	mcontext_t;
#endif

#ifndef _POSIX_C_SOURCE

struct mcontext64
{
	struct sigcontext sc;
};
#define I386_MCONTEXT64_SIZE	sizeof(struct mcontext64)	

#ifndef _MCONTEXT64_T
#define _MCONTEXT64_T
typedef struct mcontext64 * mcontext64_t;
#endif

#endif /* _POSIX_C_SOURCE */

#endif /* __APPLE_API_UNSTABLE */

#endif /* _I386_UCONTEXT_H_ */
