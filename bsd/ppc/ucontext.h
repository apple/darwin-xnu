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

#ifndef _PPC_UCONTEXT_H_
#define _PPC_UCONTEXT_H_


#include <mach/thread_status.h>

struct mcontext {
	ppc_exception_state_t	es;
	ppc_thread_state_t	ss;
	ppc_float_state_t	fs;
	ppc_vector_state_t	vs;
};

#define PPC_MCONTEXT_SIZE	(PPC_THREAD_STATE_COUNT + PPC_FLOAT_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int)

typedef struct mcontext  * mcontext_t;

struct mcontext64 {
	ppc_exception_state_t	es;
	ppc_thread_state64_t	ss;
	ppc_float_state_t	fs;
	ppc_vector_state_t	vs;
};
#define PPC_MCONTEXT64_SIZE	(PPC_THREAD_STATE64_COUNT + PPC_FLOAT_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int)

typedef struct mcontext64  * mcontext64_t;

#endif /* _PPC_UCONTEXT_H_ */
