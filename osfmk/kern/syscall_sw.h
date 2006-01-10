/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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

#ifndef	_KERN_SYSCALL_SW_H_
#define	_KERN_SYSCALL_SW_H_

#include <mach_assert.h>

/*
 *	mach_trap_stack indicates the trap may discard
 *	its kernel stack.  Some architectures may need
 *	to save more state in the pcb for these traps.
 */
typedef	void	mach_munge_t(const void *, void *);

typedef struct {
	int			mach_trap_arg_count;
	int			(*mach_trap_function)(void);
#if defined(__i386__)
	boolean_t		mach_trap_stack;
#else 
	mach_munge_t		*mach_trap_arg_munge32; /* system call arguments for 32-bit */
	mach_munge_t		*mach_trap_arg_munge64; /* system call arguments for 64-bit */
#endif
#if	!MACH_ASSERT
	int			mach_trap_unused;
#else
	const char*		mach_trap_name;
#endif /* !MACH_ASSERT */
} mach_trap_t;

#define MACH_TRAP_TABLE_COUNT   128


extern mach_trap_t		mach_trap_table[];
extern int			mach_trap_count;

#if defined(__i386__)
#if	!MACH_ASSERT
#define	MACH_TRAP(name, arg_count, munge32, munge64)	\
		{ (arg_count), (int (*)(void)) (name), FALSE, 0 }
#else
#define MACH_TRAP(name, arg_count, munge32, munge64)		\
		{ (arg_count), (int (*)(void)) (name), FALSE, #name }
#endif /* !MACH_ASSERT */
#else  /* !defined(__i386__) */
#if	!MACH_ASSERT
#define	MACH_TRAP(name, arg_count, munge32, munge64)	\
		{ (arg_count), (int (*)(void)) (name), (munge32), (munge64), 0 }
#else
#define MACH_TRAP(name, arg_count, munge32, munge64)		\
  		{ (arg_count), (int (*)(void)) (name), (munge32), (munge64), #name }
#endif /* !MACH_ASSERT */

#endif /* !defined(__i386__) */

#endif	/* _KERN_SYSCALL_SW_H_ */
