/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#ifndef	_I386_TRAP_H_
#define	_I386_TRAP_H_

/*
 * Hardware trap vectors for i386.
 */
#define	T_DIVIDE_ERROR		0
#define	T_DEBUG			1
#define	T_NMI			2		/* non-maskable interrupt */
#define	T_INT3			3		/* int 3 instruction */
#define	T_OVERFLOW		4		/* overflow test */
#define	T_OUT_OF_BOUNDS		5		/* bounds check */
#define	T_INVALID_OPCODE	6		/* invalid op code */
#define	T_NO_FPU		7		/* no floating point */
#define	T_DOUBLE_FAULT		8		/* double fault */
#define	T_FPU_FAULT		9
/*				10 */
#define	T_SEGMENT_NOT_PRESENT	11
#define	T_STACK_FAULT		12
#define	T_GENERAL_PROTECTION	13
#define	T_PAGE_FAULT		14
/*				15 */
#define	T_FLOATING_POINT_ERROR	16
#define	T_WATCHPOINT		17
#define T_PREEMPT		255

#define TRAP_NAMES "divide error", "debug trap", "NMI", "breakpoint", \
		   "overflow", "bounds check", "invalid opcode", \
		   "no coprocessor", "double fault", "coprocessor overrun", \
		   "invalid TSS", "segment not present", "stack bounds", \
		   "general protection", "page fault", "(reserved)", \
		   "coprocessor error", "watchpoint"

/*
 * Page-fault trap codes.
 */
#define	T_PF_PROT		0x1		/* protection violation */
#define	T_PF_WRITE		0x2		/* write access */
#define	T_PF_USER		0x4		/* from user state */

#if !defined(ASSEMBLER) && defined(MACH_KERNEL)

#include <i386/thread.h>

extern void		i386_exception(
				int		exc,
				int		code,
				int		subcode);

extern void		thread_exception_return(void);

extern boolean_t	kernel_trap(
				struct i386_saved_state	*regs);

extern void		panic_trap(
				struct i386_saved_state	*regs);

extern void		user_trap(
				struct i386_saved_state	*regs);

extern void		i386_astintr(int preemption);

#endif	/* !ASSEMBLER && MACH_KERNEL */

#endif	/* _I386_TRAP_H_ */
