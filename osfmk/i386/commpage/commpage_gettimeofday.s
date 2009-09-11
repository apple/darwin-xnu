/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

#define NSEC_PER_SEC	1000*1000*1000
#define NSEC_PER_USEC	1000

COMMPAGE_FUNCTION_START(gettimeofday, 32, 4)
	push	%ebp
	mov	%esp,%ebp
	push	%esi
	push	%ebx

0:
	movl	_COMM_PAGE_GTOD_GENERATION,%esi	/* get generation (0 if disabled) */
	testl	%esi,%esi			/* disabled? */
	jz	4f

	mov	$ _COMM_PAGE_NANOTIME,%eax
	call	*%eax				/* get ns in %edx:%eax */

	
	sub	_COMM_PAGE_GTOD_NS_BASE,%eax
	sbb	_COMM_PAGE_GTOD_NS_BASE+4,%edx
	mov	_COMM_PAGE_GTOD_SEC_BASE,%ebx	/* load all the data before checking generation */
	mov	$ NSEC_PER_SEC,%ecx
	
	cmpl	_COMM_PAGE_GTOD_GENERATION,%esi	/* has time data changed out from under us? */
	jne	0b
	
	div	%ecx
	add	%eax,%ebx

	mov	$ NSEC_PER_USEC,%ecx
	mov	%edx,%eax
	xor	%edx,%edx
	div	%ecx

	mov	8(%ebp),%ecx
	mov	%ebx,(%ecx)
	mov	%eax,4(%ecx)
	xor	%eax,%eax

3:
	pop	%ebx
	pop	%esi
	pop	%ebp
	ret
4:				/* fail */
	movl	$1,%eax
	jmp	3b
COMMPAGE_DESCRIPTOR(gettimeofday,_COMM_PAGE_GETTIMEOFDAY,0,0)


COMMPAGE_FUNCTION_START(gettimeofday_64, 64, 4)
	// %rdi = ptr to timeval
	pushq	%rbp			// set up a frame for backtraces
	movq	%rsp,%rbp
	movq	%rdi,%r9		// save ptr to timeval
	movq	$_COMM_PAGE_32_TO_64(_COMM_PAGE_TIME_DATA_START),%r10
0:
	movl	_GTOD_GENERATION(%r10),%r11d	// get generation (0 if disabled)
	testl	%r11d,%r11d		// disabled?
	jz	4f
	
	movq	$_COMM_PAGE_32_TO_64(_COMM_PAGE_NANOTIME),%rax
	call	*%rax			// get %rax <- nanotime(), preserving %r9, %r10 and %r11
	
	movl	_GTOD_SEC_BASE(%r10),%r8d	// get _COMM_PAGE_TIMESTAMP
	subq	_GTOD_NS_BASE(%r10),%rax	// generate nanoseconds since timestamp
	cmpl	_GTOD_GENERATION(%r10),%r11d	// has data changed out from under us?
	jne	0b
	
	movl	$ NSEC_PER_SEC,%ecx
	movq	%rax,%rdx
	shrq	$32,%rdx		// get high half of delta in %edx
	divl	%ecx			// %eax <- seconds since timestamp, %edx <- nanoseconds
	addl	%eax,%r8d		// add seconds elapsed to timestamp seconds

	movl	$ NSEC_PER_USEC,%ecx
	movl	%edx,%eax
	xorl	%edx,%edx
	divl	%ecx			// divide residual ns by 1000 to get residual us in %eax
	
	movq	%r8,(%r9)		// store 64-bit seconds into timeval
	movl	%eax,8(%r9)		// store 32-bit useconds into timeval
	xorl	%eax,%eax		// return 0 for success
3:
	popq	%rbp
	ret
4:					// fail
	movl	$1,%eax
	jmp	3b
COMMPAGE_DESCRIPTOR(gettimeofday_64,_COMM_PAGE_GETTIMEOFDAY,0,0)
