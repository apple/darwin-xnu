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
/* Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved.
 */

#include "SYS.h"

#if defined(__ppc__) || defined(__ppc64__)

/* We use mode-independent "g" opcodes such as "srgi", and/or
 * mode-independent macros such as MI_GET_ADDRESS.  These expand
 * into word operations when targeting __ppc__, and into doubleword
 * operations when targeting __ppc64__.
 */
#include <architecture/ppc/mode_independent_asm.h>

    .globl  _errno

MI_ENTRY_POINT(cerror)
    MI_PUSH_STACK_FRAME
    MI_GET_ADDRESS(r12,_errno)
    stw     r3,0(r12)               /* save syscall return code in global */
    MI_CALL_EXTERNAL(_cthread_set_errno_self)
    li      r3,-1                   /* then bug return value */
    li      r4,-1                   /* in case we're returning a long-long in 32-bit mode, etc */
    MI_POP_STACK_FRAME_AND_RETURN


    .globl _processor_facilities_used
    .align 2
_processor_facilities_used:
    li	r0,0x7FF3
    sc
    blr

#elif defined(__i386__)

	.globl	_errno

LABEL(cerror)
	REG_TO_EXTERN(%eax, _errno)
	mov		%esp,%edx
	andl	$0xfffffff0,%esp
	subl	$16,%esp
	movl	%edx,4(%esp)
	movl	%eax,(%esp)
	CALL_EXTERN(_cthread_set_errno_self)
	movl	4(%esp),%esp
	movl	$-1,%eax
	movl	$-1,%edx /* in case a 64-bit value is returned */
	ret

	.private_extern __sysenter_trap
	ALIGN
__sysenter_trap:
	popl %edx
	movl %esp, %ecx
	sysenter

#elif defined(__x86_64__)

	.globl	_errno

LABEL(cerror)
	REG_TO_EXTERN(%rax, _errno)
	mov		%rsp,%rdx
	andq	$-16,%rsp
	subq	$16,%rsp
	// Preserve the original stack
	movq	%rdx,(%rsp)
	movq	%rax,%rdi
	CALL_EXTERN(_cthread_set_errno_self)
	// Restore the original stack
	movq	(%rsp),%rsp
	movq	$-1,%rax
	movq	$-1,%rdx /* in case a 128-bit value is returned */
	ret

#else
#error Unsupported architecture
#endif

#if defined(__i386__) || defined(__x86_64__)

	.globl _i386_get_ldt
	ALIGN
_i386_get_ldt:
	movl    $6,%eax
	MACHDEP_SYSCALL_TRAP
	jnb	2f
	jmp	cerror
2:	ret


	.globl _i386_set_ldt
	ALIGN
_i386_set_ldt:
	movl    $5,%eax
	MACHDEP_SYSCALL_TRAP
	jnb	2f
	jmp	cerror
2:	ret

#endif
