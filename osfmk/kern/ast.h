/*
 * Copyright (c) 2000-2010 Apple Computer, Inc. All rights reserved.
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

#include <platforms.h>

#include <kern/assert.h>
#include <kern/macro_help.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <machine/ast.h>

/*
 * A processor takes an AST when it is about to return from an
 * interrupt context, and calls ast_taken.
 *
 * Machine-dependent code is responsible for maintaining
 * a set of reasons for an AST, and passing this set to ast_taken.
 */
typedef uint32_t		ast_t;

/*
 *      Bits for reasons
 */
#define AST_PREEMPT		0x01
#define AST_QUANTUM		0x02
#define AST_URGENT		0x04
#define AST_HANDOFF		0x08
#define AST_YIELD		0x10
#define AST_APC			0x20	/* migration APC hook */
#define AST_LEDGER		0x40

/*
 * JMM - This is here temporarily. AST_BSD is used to simulate a
 * general purpose mechanism for setting asynchronous procedure calls
 * from the outside.
 */
#define AST_BSD			0x80
#define AST_KPERF		0x100   /* kernel profiling */
#define	AST_MACF		0x200	/* MACF user ret pending */

#define AST_NONE		0x00
#define AST_ALL			(~AST_NONE)

#define AST_SCHEDULING	(AST_PREEMPTION | AST_YIELD | AST_HANDOFF)
#define AST_PREEMPTION	(AST_PREEMPT | AST_QUANTUM | AST_URGENT)

#ifdef  MACHINE_AST
/*
 *      machine/ast.h is responsible for defining aston and astoff.
 */
#else   /* MACHINE_AST */

#define aston(mycpu)
#define astoff(mycpu)

#endif  /* MACHINE_AST */

#define AST_CHUD_URGENT     0x800
#define AST_CHUD            0x400

#define AST_CHUD_ALL        (AST_CHUD_URGENT|AST_CHUD)

/* Initialize module */
extern void		ast_init(void);

/* Handle ASTs */
extern void		ast_taken(
					ast_t		mask,
					boolean_t	enable);

/* Check for pending ASTs */
extern void    	ast_check(
					processor_t		processor);

/* Pending ast mask for the current processor */
extern ast_t 	*ast_pending(void);

/*
 * Per-thread ASTs are reset at context-switch time.
 */
#ifndef MACHINE_AST_PER_THREAD
#define MACHINE_AST_PER_THREAD  0
#endif

#define AST_PER_THREAD	(AST_APC | AST_BSD | AST_MACF | MACHINE_AST_PER_THREAD | AST_LEDGER)
/*
 *	ast_pending(), ast_on(), ast_off(), ast_context(), and ast_propagate()
 *	assume splsched.
 */

#define ast_on_fast(reasons)					\
MACRO_BEGIN										\
	ast_t	*myast = ast_pending();				\
												\
	if ((*myast |= (reasons)) != AST_NONE)		\
		{ aston(myast); }						\
MACRO_END

#define ast_off_fast(reasons)					\
MACRO_BEGIN										\
	ast_t	*myast = ast_pending();				\
												\
	if ((*myast &= ~(reasons)) == AST_NONE)		\
		{ astoff(myast); }						\
MACRO_END

#define ast_propagate(reasons)		ast_on(reasons)

#define ast_context(act)													\
MACRO_BEGIN																	\
	ast_t	*myast = ast_pending();											\
																			\
	if ((*myast = ((*myast &~ AST_PER_THREAD) | (act)->ast)) != AST_NONE)	\
		{ aston(myast);	}													\
	else																	\
		{ astoff(myast); }													\
MACRO_END

#define ast_on(reason)			     ast_on_fast(reason)
#define ast_off(reason)			     ast_off_fast(reason)

/*
 *	NOTE: if thread is the current thread, thread_ast_set() should
 *  be followed by ast_propagate().
 */
#define thread_ast_set(act, reason)		\
						(hw_atomic_or_noret(&(act)->ast, (reason)))
#define thread_ast_clear(act, reason)	\
						(hw_atomic_and_noret(&(act)->ast, ~(reason)))
#define thread_ast_clear_all(act)		\
						(hw_atomic_and_noret(&(act)->ast, AST_NONE))

#ifdef MACH_BSD

extern void astbsd_on(void);
extern void act_set_astbsd(thread_t);
extern void bsd_ast(thread_t);

#endif /* MACH_BSD */

#endif  /* _KERN_AST_H_ */
