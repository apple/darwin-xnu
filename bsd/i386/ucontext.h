/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#endif /* __APPLE_API_UNSTABLE */

#endif /* _I386_UCONTEXT_H_ */
