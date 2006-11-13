/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

#define NSEC_PER_SEC	1000*1000*1000
#define NSEC_PER_USEC	1000

        .text
        .align  2, 0x90

Lgettimeofday:
	push	%ebp
	mov	%esp,%ebp
	push	%esi
	push	%edi
	push	%ebx

0:
	cmp	$0,_COMM_PAGE_TIMEENABLE
	je	4f
	mov	_COMM_PAGE_TIMEBASE,%esi
	mov	_COMM_PAGE_TIMEBASE+4,%edi
	mov	_COMM_PAGE_TIMESTAMP,%ebx

	mov	$ _COMM_PAGE_NANOTIME,%eax
	call	*%eax		/* get ns in %edx:%eax */

	cmp	_COMM_PAGE_TIMEBASE,%esi
	jne	0b
	cmp	_COMM_PAGE_TIMEBASE+4,%edi
	jne	0b
	cmp	$0,_COMM_PAGE_TIMEENABLE
	je	4f
	
	mov	$ NSEC_PER_SEC,%ecx
	sub	%esi,%eax
	sbb	%edi,%edx
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
	pop	%edi
	pop	%esi
	pop	%ebp
	ret
4:				/* fail */
	movl	$1,%eax
	jmp	3b

	COMMPAGE_DESCRIPTOR(gettimeofday,_COMM_PAGE_GETTIMEOFDAY,0,0)


	.code64
        .text
        .align  2, 0x90

Lgettimeofday_64:			// %rdi = ptr to timeval
	pushq	%rbp			// set up a frame for backtraces
	movq	%rsp,%rbp
	movq	%rdi,%r9		// save ptr to timeval
	movq	$_COMM_PAGE_32_TO_64(_COMM_PAGE_TIMEBASE),%r10
0:
	cmpl	$0,_TIMEENABLE(%r10)	// is data valid? (test _COMM_PAGE_TIMEENABLE)
	jz	4f			// no
	movq	_TIMEBASE(%r10),%r11	// get _COMM_PAGE_TIMEBASE
	movq	$_COMM_PAGE_32_TO_64(_COMM_PAGE_NANOTIME),%rax
	call	*%rax			// get %rax <- nanotime(), preserving %r9, %r10 and %r11
	movl	_TIMESTAMP(%r10),%r8d	// get _COMM_PAGE_TIMESTAMP
	cmpq	_TIMEBASE(%r10),%r11	// has _COMM_PAGE_TIMEBASE changed?
	jne	0b			// loop until we have consistent data
	cmpl	$0,_TIMEENABLE(%r10)	// is data valid? (test _COMM_PAGE_TIMEENABLE)
	jz	4f			// no
	
	movl	$ NSEC_PER_SEC,%ecx
	subq	%r11,%rax		// generate nanoseconds since timestamp
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
