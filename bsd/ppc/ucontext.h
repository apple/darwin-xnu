/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _PPC_UCONTEXT_H_
#define _PPC_UCONTEXT_H_


#include <mach/ppc/_types.h>

#ifndef _POSIX_C_SOURCE
struct mcontext {
	struct ppc_exception_state	es;
	struct ppc_thread_state		ss;
	struct ppc_float_state		fs;
	struct ppc_vector_state		vs;
};
#define PPC_MCONTEXT_SIZE	(PPC_THREAD_STATE_COUNT + PPC_FLOAT_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int)
#else /* _POSIX_C_SOURCE */
struct __darwin_mcontext {
	struct __darwin_ppc_exception_state	es;
	struct __darwin_ppc_thread_state	ss;
	struct __darwin_ppc_float_state		fs;
	struct __darwin_ppc_vector_state	vs;
};
#endif /* _POSIX_C_SOURCE */

#ifndef _MCONTEXT_T
#define _MCONTEXT_T
typedef __darwin_mcontext_t		mcontext_t;
#endif

#ifndef _POSIX_C_SOURCE
struct mcontext64 {
	struct ppc_exception_state64	es;
	struct ppc_thread_state64	ss;
	struct ppc_float_state		fs;
	struct ppc_vector_state		vs;
};
#define PPC_MCONTEXT64_SIZE	(PPC_THREAD_STATE64_COUNT + PPC_FLOAT_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int)

#ifndef _MCONTEXT64_T
#define _MCONTEXT64_T
typedef struct mcontext64  * mcontext64_t;
#endif

#endif /* _POSIX_C_SOURCE */

#endif /* _PPC_UCONTEXT_H_ */
