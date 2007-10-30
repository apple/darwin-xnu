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
#include <i386/asm.h>

#include <assym.s>

        .text
        .align  2, 0x90

Lmach_absolute_time:
	int	$0x3
	ret

	COMMPAGE_DESCRIPTOR(mach_absolute_time,_COMM_PAGE_ABSOLUTE_TIME,0,0)

 
/* return nanotime in %edx:%eax */

Lnanotime:
	pushl	%ebp
	movl	%esp,%ebp
	pushl	%esi
	pushl	%ebx

0:
	movl	_COMM_PAGE_NT_GENERATION,%esi	/* get generation (0 if being changed) */
	testl	%esi,%esi			/* if being updated, loop until stable */
	jz	0b

	rdtsc					/* get TSC in %edx:%eax */
	subl	_COMM_PAGE_NT_TSC_BASE,%eax
	sbbl	_COMM_PAGE_NT_TSC_BASE+4,%edx

	movl	_COMM_PAGE_NT_SCALE,%ecx

	movl	%edx,%ebx
	mull	%ecx
	movl	%ebx,%eax
	movl	%edx,%ebx
	mull	%ecx
	addl	%ebx,%eax
	adcl	$0,%edx

	addl	_COMM_PAGE_NT_NS_BASE,%eax
	adcl	_COMM_PAGE_NT_NS_BASE+4,%edx

	cmpl	_COMM_PAGE_NT_GENERATION,%esi	/* have the parameters changed? */
	jne	0b				/* yes, loop until stable */

	popl	%ebx
	popl	%esi
	popl	%ebp
	ret

	COMMPAGE_DESCRIPTOR(nanotime,_COMM_PAGE_NANOTIME,0,kSlow)


/* nanotime routine for machines slower than ~1Gz (SLOW_TSC_THRESHOLD) */
Lnanotime_slow:
	push	%ebp
	mov	%esp,%ebp
	push	%esi
	push	%edi
	push	%ebx

0:
	movl	_COMM_PAGE_NT_GENERATION,%esi
	testl	%esi,%esi			/* if generation is 0, data being changed */
	jz	0b				/* so loop until stable */

	rdtsc					/* get TSC in %edx:%eax */
	subl	_COMM_PAGE_NT_TSC_BASE,%eax
	sbbl	_COMM_PAGE_NT_TSC_BASE+4,%edx

	pushl	%esi				/* save generation */
	/*
	 * Do the math to convert tsc ticks to nanoseconds.  We first
	 * do long multiply of 1 billion times the tsc.  Then we do
	 * long division by the tsc frequency
	 */
	mov	$1000000000, %ecx		/* number of nanoseconds in a second */
	mov	%edx, %ebx
	mul	%ecx
	mov	%edx, %edi
	mov	%eax, %esi
	mov	%ebx, %eax
	mul	%ecx
	add	%edi, %eax
	adc	$0, %edx			/* result in edx:eax:esi */
	mov	%eax, %edi
	mov	_COMM_PAGE_NT_SHIFT,%ecx	/* overloaded as the low 32 tscFreq */
	xor	%eax, %eax
	xchg	%edx, %eax
	div	%ecx
	xor	%eax, %eax
	mov	%edi, %eax
	div	%ecx
	mov	%eax, %ebx
	mov	%esi, %eax
	div	%ecx
	mov	%ebx, %edx			/* result in edx:eax */
	popl	%esi				/* recover generation */

	add	_COMM_PAGE_NT_NS_BASE,%eax
	adc	_COMM_PAGE_NT_NS_BASE+4,%edx

	cmpl	_COMM_PAGE_NT_GENERATION,%esi	/* have the parameters changed? */
	jne	0b				/* yes, loop until stable */

	pop	%ebx
	pop	%edi
	pop	%esi
	pop	%ebp
	ret					/* result in edx:eax */

	COMMPAGE_DESCRIPTOR(nanotime_slow,_COMM_PAGE_NANOTIME,kSlow,0)


/* The 64-bit version.  We return the 64-bit nanotime in %rax,
 * and by convention we must preserve %r9, %r10, and %r11.
 */
	.text
	.align	2
	.code64
Lnanotime_64:					// NB: must preserve r9, r10, and r11
	pushq	%rbp				// set up a frame for backtraces
	movq	%rsp,%rbp
	movq	$_COMM_PAGE_32_TO_64(_COMM_PAGE_TIME_DATA_START),%rsi
1:
	movl	_NT_GENERATION(%rsi),%r8d	// get generation
	testl	%r8d,%r8d			// if 0, data is being changed...
	jz	1b				// ...so loop until stable
	rdtsc					// edx:eax := tsc
	shlq	$32,%rdx			// rax := ((edx << 32) | eax), ie 64-bit tsc
	orq	%rdx,%rax
	subq	_NT_TSC_BASE(%rsi), %rax	// rax := (tsc - base_tsc)
	movl	_NT_SCALE(%rsi),%ecx
	mulq	%rcx				// rdx:rax := (tsc - base_tsc) * scale
	shrdq	$32,%rdx,%rax			// _COMM_PAGE_NT_SHIFT is always 32
	addq	_NT_NS_BASE(%rsi),%rax		// (((tsc - base_tsc) * scale) >> 32) + ns_base
	
	cmpl	_NT_GENERATION(%rsi),%r8d	// did the data change during computation?
	jne	1b
	popq	%rbp
	ret

	COMMPAGE_DESCRIPTOR(nanotime_64,_COMM_PAGE_NANOTIME,0,kSlow)
