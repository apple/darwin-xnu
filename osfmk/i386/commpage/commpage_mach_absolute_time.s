/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

	COMMPAGE_DESCRIPTOR(mach_absolute_time,_COMM_PAGE_ABSOLUTE_TIME,1,0)


Lnanotime:

	pushl	%ebx
	pushl	%esi
	pushl	%edi
	pushl	%ebp
	movl	$(_COMM_PAGE_NANOTIME_INFO), %esi

	/*
	 * The nanotime info consists of:
	 *	- base_tsc	64-bit timestamp register value
	 *	- base_ns	64-bit corresponding nanosecond uptime value
	 *	- scale		32-bit current scale multiplier
	 *	- shift		32-bit current shift divider
	 *	- check_tsc	64-bit timestamp check value
	 *
	 * This enables an timestamp register's value, tsc, to be converted
	 * into a nanosecond nanotime value, ns:
	 *
	 * 	ns = base_ns + ((tsc - base_tsc) * scale >> shift)
	 *
	 * The kernel updates this every tick or whenever a performance
	 * speed-step changes the scaling. To avoid locking, a duplicated
	 * sequence counting scheme is used. The base_tsc value is updated
	 * whenever the info starts to be changed, and check_tsc is updated
	 * to the same value at the end of the update. The regularity of
	 * update ensures that (tsc - base_tsc) is a 32-bit quantity.
	 * When a conversion is performed, we read base_tsc before we start
	 * and check_tsc at the end -- if there's a mis-match we repeat.
	 * It's sufficient to compare only the low-order 32-bits. 
	 */

1:
	//
	//  Read nanotime info and stash in registers.
	//
	movl	NANOTIME_BASE_TSC(%esi), %ebx	// ebx := lo(base_tsc)
	movl	NANOTIME_BASE_NS(%esi), %ebp
	movl	NANOTIME_BASE_NS+4(%esi), %edi	// edi:ebp := base_ns
	movl	NANOTIME_SHIFT(%esi), %ecx	// ecx := shift
	//
	// Read timestamp register (tsc) and calculate delta.
	//
	rdtsc					// edx:eax := tsc
	subl	%ebx, %eax			// eax := (tsc - base_tsc)
	movl	NANOTIME_SCALE(%esi), %edx	// edx := shift
	//
	// Check for consistency and re-read if necessary.
	//
	cmpl	NANOTIME_CHECK_TSC(%esi), %ebx
	jne	1b

	//
	// edx:eax := ((tsc - base_tsc) * scale)
	//
	mull	%edx

	//
	// eax := ((tsc - base_tsc) * scale >> shift)
	//
	shrdl	%cl, %edx, %eax
	andb	$32, %cl
	cmovnel	%edx, %eax		// %eax := %edx if shift == 32
	xorl	%edx, %edx

	//
	// Add base_ns: 
	// edx:eax = (base_ns + ((tsc - base_tsc) * scale >> shift))
	//
	addl	%ebp, %eax
	adcl	%edi, %edx

	popl	%ebp
	popl	%edi
	popl	%esi
	popl	%ebx
	ret

	COMMPAGE_DESCRIPTOR(nanotime,_COMM_PAGE_NANOTIME,1,0)
