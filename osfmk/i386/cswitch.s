/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <platforms.h>

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <assym.s>

#if	NCPUS > 1

#ifdef	SYMMETRY
#include <sqt/asm_macros.h>
#endif

#if	AT386
#include <i386/AT386/mp/mp.h>
#endif	/* AT386 */

#define	CX(addr, reg)	addr(,reg,4)

#else	/* NCPUS == 1 */

#define	CPU_NUMBER(reg)
#define	CX(addr,reg)	addr

#endif	/* NCPUS == 1 */

/*
 * Context switch routines for i386.
 */

Entry(Load_context)
	movl	S_ARG0,%ecx			/* get thread */
	movl	TH_KERNEL_STACK(%ecx),%ecx	/* get kernel stack */
	lea	KERNEL_STACK_SIZE-IKS_SIZE-IEL_SIZE(%ecx),%edx
						/* point to stack top */
	CPU_NUMBER(%eax)
	movl	%ecx,CX(EXT(active_stacks),%eax) /* store stack address */
	movl	%edx,CX(EXT(kernel_stack),%eax)	/* store stack top */

	movl	KSS_ESP(%ecx),%esp		/* switch stacks */
	movl	KSS_ESI(%ecx),%esi		/* restore registers */
	movl	KSS_EDI(%ecx),%edi
	movl	KSS_EBP(%ecx),%ebp
	movl	KSS_EBX(%ecx),%ebx
	xorl	%eax,%eax			/* return zero (no old thread) */
	jmp	*KSS_EIP(%ecx)			/* resume thread */

/*
 *	This really only has to save registers
 *	when there is no explicit continuation.
 */

Entry(Switch_context)
	CPU_NUMBER(%edx)
	movl	CX(EXT(active_stacks),%edx),%ecx /* get old kernel stack */

	movl	%ebx,KSS_EBX(%ecx)		/* save registers */
	movl	%ebp,KSS_EBP(%ecx)
	movl	%edi,KSS_EDI(%ecx)
	movl	%esi,KSS_ESI(%ecx)
	popl	KSS_EIP(%ecx)			/* save return PC */
	movl	%esp,KSS_ESP(%ecx)		/* save SP */

	movl	0(%esp),%eax			/* get old thread */
	movl	4(%esp),%ebx			/* get continuation */
	movl	%ebx,TH_CONTINUATION(%eax)	/* save continuation */
	movl	%ecx,TH_KERNEL_STACK(%eax)	/* save kernel stack */

	movl	8(%esp),%esi			/* get new thread */
        movl    $ CPD_ACTIVE_THREAD,%ecx
        movl    %esi,%gs:(%ecx)                 /* new thread is active */
	movl	TH_KERNEL_STACK(%esi),%ecx	/* get its kernel stack */
	lea	KERNEL_STACK_SIZE-IKS_SIZE-IEL_SIZE(%ecx),%ebx
						/* point to stack top */

	movl	%ecx,CX(EXT(active_stacks),%edx) /* set current stack */
	movl	%ebx,CX(EXT(kernel_stack),%edx)	/* set stack top */

	movl	TH_TOP_ACT(%esi),%esi		/* get new_thread->top_act */
	cmpl	$0,ACT_KLOADED(%esi)		/* check kernel-loaded flag */
	je	0f
	movl	%esi,CX(EXT(active_kloaded),%edx)
	jmp	1f
0:
	movl	$0,CX(EXT(active_kloaded),%edx)
1:
	movl	KSS_ESP(%ecx),%esp		/* switch stacks */
	movl	KSS_ESI(%ecx),%esi		/* restore registers */
	movl	KSS_EDI(%ecx),%edi
	movl	KSS_EBP(%ecx),%ebp
	movl	KSS_EBX(%ecx),%ebx
	jmp	*KSS_EIP(%ecx)			/* return old thread */

Entry(Thread_continue)
	pushl	%eax				/* push the thread argument */
	xorl	%ebp,%ebp			/* zero frame pointer */
	call	*%ebx				/* call real continuation */

#if	NCPUS > 1
/*
 * void switch_to_shutdown_context(thread_t thread,
 *				   void (*routine)(processor_t),
 *				   processor_t processor)
 *
 * saves the kernel context of the thread,
 * switches to the interrupt stack,
 * continues the thread (with thread_continue),
 * then runs routine on the interrupt stack.
 *
 * Assumes that the thread is a kernel thread (thus
 * has no FPU state)
 */
Entry(switch_to_shutdown_context)
	CPU_NUMBER(%edx)
	movl	EXT(active_stacks)(,%edx,4),%ecx /* get old kernel stack */
	movl	%ebx,KSS_EBX(%ecx)		/* save registers */
	movl	%ebp,KSS_EBP(%ecx)
	movl	%edi,KSS_EDI(%ecx)
	movl	%esi,KSS_ESI(%ecx)
	popl	KSS_EIP(%ecx)			/* save return PC */
	movl	%esp,KSS_ESP(%ecx)		/* save SP */

	movl	0(%esp),%eax			/* get old thread */
	movl	$0,TH_CONTINUATION(%eax)	/* clear continuation */
	movl	%ecx,TH_KERNEL_STACK(%eax)	/* save old stack */
	movl	4(%esp),%ebx			/* get routine to run next */
	movl	8(%esp),%esi			/* get its argument */

	movl	CX(EXT(interrupt_stack),%edx),%ecx /* point to its intr stack */
	lea	INTSTACK_SIZE(%ecx),%esp	/* switch to it (top) */
	
	pushl	%eax				/* push thread */
	call	EXT(thread_dispatch)		/* reschedule thread */
	addl	$4,%esp				/* clean stack */

	pushl	%esi				/* push argument */
	call	*%ebx				/* call routine to run */
	hlt					/* (should never return) */

#endif	/* NCPUS > 1 */

        .text

	.globl	EXT(locore_end)
LEXT(locore_end)

