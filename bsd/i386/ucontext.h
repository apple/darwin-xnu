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
#include <signal.h>


#ifdef __APPLE_API_UNSTABLE
/* WARNING: THIS WILL CHANGE;  DO NOT COUNT ON THIS */
/* Needs to be finalized as to what it should contain */
struct mcontext {
	struct sigcontext sc;
};

#define I386_MCONTEXT_SIZE	sizeof(struct mcontext)	

typedef struct mcontext * mcontext_t;

struct mcontext64 {
	struct sigcontext sc;
};
#define I386_MCONTEXT64_SIZE	sizeof(struct mcontext64)	

typedef struct mcontext64 * mcontext64_t;

#endif /* __APPLE_API_UNSTABLE */

#endif /* _I386_UCONTEXT_H_ */
