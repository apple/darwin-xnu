/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 /*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <i386/asm.h>

/*
 * void *secure_memset(void * addr, int pattern, size_t length)
 *
 * It is important that this function remains defined in assembly to avoid
 * compiler optimizations.
 */
ENTRY(secure_memset)
/*
 * void *memset(void * addr, int pattern, size_t length)
 */

ENTRY(memset)
	movq	%rdi, %r8
	movq	%rsi, %rax		/* move pattern (arg2) to rax */
	movb	%al,%ah			/* fill out pattern */
	movw	%ax,%cx
	shll	$16,%eax
	movw	%cx,%ax	
	mov		%eax, %ecx
	shlq	$32,%rax
	orq		%rcx, %rax 
	cld						/* reset direction flag */
	movq 	%rdx, %rcx		/* mov quads first */
	shrq	$3, %rcx
	rep
	stosq
	movq	%rdx,%rcx		/* mov bytes */
	andq	$7,%rcx
	rep
	stosb
	movq	%r8 ,%rax		/* returns its first argument */
	ret

/*
 * void *memset_word(void * addr, int pattern, size_t length)
 */

ENTRY(memset_word)
	movq	%rdi, %r8
	movq	%rsi, %rax		/* move pattern (arg2) to rax */
	mov	%eax, %ecx
	shlq	$32,%rax
	orq	%rcx, %rax 
	cld				/* reset direction flag */
	movq 	%rdx, %rcx		/* mov quads first */
	shrq	$1, %rcx
	rep
	stosq
	movq	%rdx,%rcx		/* if necessary, mov 32 bit word */
	andq	$1,%rcx
	rep
	stosl
	movq	%r8 ,%rax		/* returns its first argument */
	ret

/*
 * void bzero(char * addr, size_t length)
 */
Entry(blkclr)
ENTRY2(bzero,__bzero)
	movq	%rsi,%rcx
	xorq	%rax,%rax
	shrq	$3,%rcx
	cld
	rep
	stosq
	movq	%rsi,%rcx
	andq	$7,%rcx
	rep
	stosb
	ret
