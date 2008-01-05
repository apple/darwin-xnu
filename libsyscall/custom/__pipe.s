/*
 * Copyright (c) 1999-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. */

#include "SYS.h"

#if defined(__ppc__) || defined(__ppc64__)

MI_ENTRY_POINT(___pipe)
    mr      r12,r3              // save fildes across syscall
	SYSCALL_NONAME(pipe, 0)
	stw     r3,0(r12)
	stw     r4,4(r12)
	li      r3,0
	blr

#elif defined(__i386__)

PSEUDO_INT(__pipe, pipe, 0)
	movl	4(%esp),%ecx
	movl	%eax,(%ecx)
	movl	%edx,4(%ecx)
	xorl	%eax,%eax
	ret

#elif defined(__x86_64__)

PSEUDO(__pipe, pipe, 0)
	movl	%eax, (%rdi)
	movl	%edx, 4(%rdi)
	xorl	%eax, %eax
	ret

#else
#error Unsupported architecture
#endif
