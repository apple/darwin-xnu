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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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

/*
 *      kern/ast.h: Definitions for Asynchronous System Traps.
 */

#ifndef _KERN_AST_H_
#define _KERN_AST_H_

#include <cpus.h>
#include <platforms.h>

#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/macro_help.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <machine/ast.h>

/*
 *      A CPU takes an AST when it is about to return to user code.
 *      Instead of going back to user code, it calls ast_taken.
 *      Machine-dependent code is responsible for maintaining
 *      a set of reasons for an AST, and passing this set to ast_taken.
 */
typedef unsigned int	ast_t;

/*
 *      Bits for reasons
 */
#define AST_HALT		0x01
#define AST_TERMINATE	0x02
#define AST_BLOCK       0x04
#define AST_QUANTUM     0x08
#define	AST_URGENT		0x10
#define AST_APC			0x20	/* migration APC hook */
/*
 * JMM - This is here temporarily. AST_BSD is used to simulate a
 * general purpose mechanism for setting asynchronous procedure calls
 * from the outside.
 */
#define	AST_BSD			0x80
#define	AST_BSD_INIT	0x100

#define AST_NONE		0x00
#define	AST_ALL			(~AST_NONE)

#define AST_SCHEDULING	(AST_HALT | AST_TERMINATE | AST_BLOCK)
#define	AST_PREEMPT		(AST_BLOCK | AST_QUANTUM | AST_URGENT)

extern volatile ast_t	need_ast[NCPUS];

#ifdef  MACHINE_AST
/*
 *      machine/ast.h is responsible for defining aston and astoff.
 */
#else   /* MACHINE_AST */

#define aston(mycpu)
#define astoff(mycpu)

#endif  /* MACHINE_AST */

/* Initialize module */
extern void		ast_init(void);

/* Handle ASTs */
extern void		ast_taken(
					ast_t		mask,
					boolean_t	enable);

/* Check for pending ASTs */
extern void    	ast_check(void);

/*
 * Per-thread ASTs are reset at context-switch time.
 */
#ifndef MACHINE_AST_PER_THREAD
#define MACHINE_AST_PER_THREAD  0
#endif

#define AST_PER_THREAD	(	AST_HALT | AST_TERMINATE | AST_APC | AST_BSD |	\
										MACHINE_AST_PER_THREAD	)
/*
 *	ast_needed(), ast_on(), ast_off(), ast_context(), and ast_propagate()
 *	assume splsched.
 */
#define ast_needed(mycpu)			need_ast[mycpu]

#define ast_on_fast(reasons)							\
MACRO_BEGIN												\
	int		mycpu = cpu_number();						\
	if ((need_ast[mycpu] |= (reasons)) != AST_NONE)		\
		{ aston(mycpu); }								\
MACRO_END

#define ast_off_fast(reasons)							\
MACRO_BEGIN												\
	int		mycpu = cpu_number();						\
	if ((need_ast[mycpu] &= ~(reasons)) == AST_NONE)	\
		{ astoff(mycpu); }				 				\
MACRO_END

#define ast_propagate(reasons)		ast_on(reasons)

#define ast_context(act, mycpu)							\
MACRO_BEGIN												\
	assert((mycpu) == cpu_number());					\
	if ((need_ast[mycpu] =								\
			((need_ast[mycpu] &~ AST_PER_THREAD) | (act)->ast)) != AST_NONE) \
		{ aston(mycpu);	}								\
	else												\
		{ astoff(mycpu); }								\
MACRO_END

#define ast_on(reason)			     ast_on_fast(reason)
#define ast_off(reason)			     ast_off_fast(reason)

#define thread_ast_set(act, reason)			((act)->ast |= (reason))
#define thread_ast_clear(act, reason)		((act)->ast &= ~(reason))
#define thread_ast_clear_all(act)			((act)->ast = AST_NONE)

/*
 *	NOTE: if thread is the current thread, thread_ast_set() should
 *  be followed by ast_propagate().
 */

#ifdef MACH_KERNEL_PRIVATE

#define ast_urgency()		(need_ast[cpu_number()] & AST_URGENT)

#endif /* MACH_KERNEL_PRIVATE */

#endif  /* _KERN_AST_H_ */
