/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/proc_reg.h>
#include <assym.s>

Entry(Load_context)
	movq	TH_KERNEL_STACK(%rdi),%rcx	/* get kernel stack */
	leaq	-IKS_SIZE(%rcx),%rdx
	addq	EXT(kernel_stack_size)(%rip),%rdx /* point to stack top */
	movq	%rcx,%gs:CPU_ACTIVE_STACK	/* store stack address */
	movq	%rdx,%gs:CPU_KERNEL_STACK	/* store stack top */

	movq	%rdx,%rsp
	movq	%rdx,%rbp

	xorq	%rdi,%rdi			/* return zero (no old thread) */
	call	EXT(thread_continue)


/*
 * thread_t Switch_context(
 *		thread_t old,				// %rsi
 *		thread_continue_t continuation,		// %rdi
 *		thread_t new)				// %rdx
 */
Entry(Switch_context)
	popq	%rax				/* pop return PC */

	/* Test for a continuation and skip all state saving if so... */
	cmpq	$0, %rsi
	jne 	5f
	movq	%gs:CPU_KERNEL_STACK,%rcx	/* get old kernel stack top */
	movq	%rbx,KSS_RBX(%rcx)		/* save registers */
	movq	%rbp,KSS_RBP(%rcx)
	movq	%r12,KSS_R12(%rcx)
	movq	%r13,KSS_R13(%rcx)
	movq	%r14,KSS_R14(%rcx)
	movq	%r15,KSS_R15(%rcx)
	movq	%rax,KSS_RIP(%rcx)		/* save return PC */
	movq	%rsp,KSS_RSP(%rcx)		/* save SP */
5:
	movq	%rdi,%rax			/* return old thread */
	/* new thread in %rdx */
	movq    %rdx,%gs:CPU_ACTIVE_THREAD      /* new thread is active */
	movq	TH_KERNEL_STACK(%rdx),%rdx	/* get its kernel stack */
	lea	-IKS_SIZE(%rdx),%rcx
	add	EXT(kernel_stack_size)(%rip),%rcx /* point to stack top */

	movq	%rdx,%gs:CPU_ACTIVE_STACK	/* set current stack */
	movq	%rcx,%gs:CPU_KERNEL_STACK	/* set stack top */

	movq	KSS_RSP(%rcx),%rsp		/* switch stacks */
	movq	KSS_RBX(%rcx),%rbx		/* restore registers */
	movq	KSS_RBP(%rcx),%rbp
	movq	KSS_R12(%rcx),%r12
	movq	KSS_R13(%rcx),%r13
	movq	KSS_R14(%rcx),%r14
	movq	KSS_R15(%rcx),%r15
	jmp	*KSS_RIP(%rcx)			/* return old thread */


Entry(Thread_continue)
	movq	%rax, %rdi			/* load thread argument */
	xorq	%rbp,%rbp			/* zero frame pointer */
	call	*%rbx				/* call real continuation */


/*
 * thread_t Shutdown_context(
 *		thread_t thread,		// %rdi
 *		void (*routine)(processor_t),	// %rsi
 *		processor_t processor)		// %rdx
 *
 * saves the kernel context of the thread,
 * switches to the interrupt stack,
 * continues the thread (with thread_continue),
 * then runs routine on the interrupt stack.
 *
 */
Entry(Shutdown_context)
	movq	%gs:CPU_KERNEL_STACK,%rcx	/* get old kernel stack top */
	movq	%rbx,KSS_RBX(%rcx)		/* save registers */
	movq	%rbp,KSS_RBP(%rcx)
	movq	%r12,KSS_R12(%rcx)
	movq	%r13,KSS_R13(%rcx)
	movq	%r14,KSS_R14(%rcx)
	movq	%r15,KSS_R15(%rcx)
	popq	KSS_RIP(%rcx)			/* save return PC */
	movq	%rsp,KSS_RSP(%rcx)		/* save SP */

	movq	%gs:CPU_ACTIVE_STACK,%rcx	/* get old kernel stack */
	movq	%rdi,%rax			/* get old thread */
	movq	%rcx,TH_KERNEL_STACK(%rax)	/* save old stack */

	movq	%gs:CPU_INT_STACK_TOP,%rsp 	/* switch to interrupt stack */

	movq	%rdx,%rdi			/* processor arg to routine */
	call	*%rsi				/* call routine to run */
	hlt					/* (should never return) */

