/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 1989 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <mach_ldebug.h>
#include <i386/asm.h>
#include <i386/eflags.h>
#include <i386/trap.h>
#include <config_dtrace.h>
#include <i386/mp.h>

#include "assym.s"

#define	PAUSE		rep; nop

#include <i386/pal_lock_asm.h>

#define LEAF_ENTRY(name)	\
	Entry(name)

#define LEAF_RET		\
	ret

/* For x86_64, the varargs ABI requires that %al indicate
 * how many SSE register contain arguments. In our case, 0 */
#define ALIGN_STACK() 		and  $0xFFFFFFFFFFFFFFF0, %rsp ;
#define LOAD_STRING_ARG0(label)	leaq label(%rip), %rdi ;
#define LOAD_ARG1(x)		mov x, %esi ;
#define LOAD_PTR_ARG1(x)	mov x, %rsi ;
#define CALL_PANIC()		xorb %al,%al ; call EXT(panic) ;

#define PREEMPTION_DISABLE				\
	incl	%gs:CPU_PREEMPTION_LEVEL

#define	PREEMPTION_LEVEL_DEBUG 1	
#if	PREEMPTION_LEVEL_DEBUG
#define	PREEMPTION_ENABLE				\
	decl	%gs:CPU_PREEMPTION_LEVEL	;	\
	js	17f				;	\
	jnz	19f				;	\
	testl	$AST_URGENT,%gs:CPU_PENDING_AST	;	\
	jz	19f				;	\
	PUSHF					;	\
	testl	$EFL_IF, S_PC			;	\
	jz	18f				;	\
	POPF					;	\
	int	$(T_PREEMPT)			;	\
	jmp	19f				;	\
17:							\
	call	_preemption_underflow_panic	;	\
18:							\
	POPF					;	\
19:
#else
#define	PREEMPTION_ENABLE				\
	decl	%gs:CPU_PREEMPTION_LEVEL	;	\
	jnz	19f				;	\
	testl	$AST_URGENT,%gs:CPU_PENDING_AST	;	\
	jz	19f				;	\
	PUSHF					;	\
	testl	$EFL_IF, S_PC			;	\
	jz	18f				;	\
	POPF					;	\
	int	$(T_PREEMPT)			;	\
	jmp	19f				;	\
18:							\
	POPF					;	\
19:
#endif

/*
 * For most routines, the hw_lock_t pointer is loaded into a
 * register initially, and then either a byte or register-sized
 * word is loaded/stored to the pointer
 */

/*
 *	void hw_lock_byte_init(volatile uint8_t *)
 *
 *	Initialize a hardware byte lock.
 */
LEAF_ENTRY(hw_lock_byte_init)
	movb	$0, (%rdi)		/* clear the lock */
	LEAF_RET

/*
 *	void	hw_lock_byte_lock(uint8_t *lock_byte)
 *
 *	Acquire byte sized lock operand, spinning until it becomes available.
 *	return with preemption disabled.
 */

LEAF_ENTRY(hw_lock_byte_lock)
	PREEMPTION_DISABLE
	movl	$1, %ecx		/* Set lock value */
1:
	movb	(%rdi), %al		/* Load byte at address */
	testb	%al,%al			/* lock locked? */
	jne	3f			/* branch if so */
	lock; cmpxchg %cl,(%rdi)	/* attempt atomic compare exchange */
	jne	3f
	LEAF_RET			/* if yes, then nothing left to do */
3:
	PAUSE				/* pause for hyper-threading */
	jmp	1b			/* try again */

/*
 *	void hw_lock_byte_unlock(uint8_t *lock_byte)
 *
 *	Unconditionally release byte sized lock operand,
 *	release preemption level.
 */

LEAF_ENTRY(hw_lock_byte_unlock)
	movb $0, (%rdi)		/* Clear the lock byte */
	PREEMPTION_ENABLE
	LEAF_RET

LEAF_ENTRY(preemption_underflow_panic)
	FRAME
	incl	%gs:CPU_PREEMPTION_LEVEL
	ALIGN_STACK()
	LOAD_STRING_ARG0(16f)
	CALL_PANIC()
	hlt
	.data
16:	String	"Preemption level underflow, possible cause unlocking an unlocked mutex or spinlock"
	.text

