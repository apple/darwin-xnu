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
 *	File:	machine/thread.h
 *
 *	This file contains the structure definitions for the thread
 *	state as applied to I386 processors.
 */

#ifndef	_I386_THREAD_H_
#define _I386_THREAD_H_

#include <mach/boolean.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/fp_reg.h>

#include <kern/lock.h>

#include <i386/iopb.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/eflags.h>
#include <i386/thread_act.h>

/*
 *	i386_exception_link:
 *
 *	This structure lives at the high end of the kernel stack.
 *	It points to the current thread`s user registers.
 */
struct i386_exception_link {
	struct i386_saved_state *saved_state;
};


/*
 *	On the kernel stack is:
 *	stack:	...
 *		struct i386_exception_link
 *		struct i386_kernel_state
 *	stack+KERNEL_STACK_SIZE
 */

#define STACK_IKS(stack)	\
	((struct i386_kernel_state *)((stack) + KERNEL_STACK_SIZE) - 1)
#define STACK_IEL(stack)	\
	((struct i386_exception_link *)STACK_IKS(stack) - 1)

#if	NCPUS > 1
#include <i386/mp_desc.h>
#endif

/*
 * Boot-time data for master (or only) CPU
 */
extern struct fake_descriptor	idt[IDTSZ];
extern struct fake_descriptor	gdt[GDTSZ];
extern struct fake_descriptor	ldt[LDTSZ];
extern struct i386_tss		ktss;
#if	MACH_KDB
extern char			db_stack_store[];
extern char			db_task_stack_store[];
extern struct i386_tss		dbtss;
extern void			db_task_start(void);
#endif	/* MACH_KDB */
#if	NCPUS > 1
#define	curr_gdt(mycpu)		(mp_gdt[mycpu])
#define	curr_ktss(mycpu)	(mp_ktss[mycpu])
#else
#define	curr_gdt(mycpu)		(gdt)
#define	curr_ktss(mycpu)	(&ktss)
#endif

#define	gdt_desc_p(mycpu,sel) \
	((struct real_descriptor *)&curr_gdt(mycpu)[sel_idx(sel)])

/*
 * Return address of the function that called current function, given
 *	address of the first parameter of current function.
 */
#define	GET_RETURN_PC(addr)	(*((vm_offset_t *)addr - 1))

/*
 * Defining this indicates that MD code will supply an exception()
 * routine, conformant with kern/exception.c (dependency alert!)
 * but which does wonderfully fast, machine-dependent magic.
 */
#define MACHINE_FAST_EXCEPTION 1

/*
 * MD Macro to fill up global stack state,
 * keeping the MD structure sizes + games private
 */
#define MACHINE_STACK_STASH(stack)                                      \
MACRO_BEGIN								\
	mp_disable_preemption();					\
	kernel_stack[cpu_number()] = (stack) +                          \
	    (KERNEL_STACK_SIZE - sizeof (struct i386_exception_link)    \
				- sizeof (struct i386_kernel_state)),   \
		active_stacks[cpu_number()] = (stack);			\
	mp_enable_preemption();						\
MACRO_END

#endif	/* _I386_THREAD_H_ */
