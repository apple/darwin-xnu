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

#ifndef	_MACH_EXCEPTION_TYPES_H_
#define	_MACH_EXCEPTION_TYPES_H_

#include <mach/machine/exception.h>

/*
 *	Machine-independent exception definitions.
 */


#define EXC_BAD_ACCESS		1	/* Could not access memory */
		/* Code contains kern_return_t describing error. */
		/* Subcode contains bad memory address. */

#define EXC_BAD_INSTRUCTION	2	/* Instruction failed */
		/* Illegal or undefined instruction or operand */

#define EXC_ARITHMETIC		3	/* Arithmetic exception */
		/* Exact nature of exception is in code field */

#define EXC_EMULATION		4	/* Emulation instruction */
		/* Emulation support instruction encountered */
		/* Details in code and subcode fields	*/

#define EXC_SOFTWARE		5	/* Software generated exception */
		/* Exact exception is in code field. */
		/* Codes 0 - 0xFFFF reserved to hardware */
		/* Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix) */

#define EXC_BREAKPOINT		6	/* Trace, breakpoint, etc. */
		/* Details in code field. */

#define EXC_SYSCALL		7	/* System calls. */

#define EXC_MACH_SYSCALL	8	/* Mach system calls. */

#define EXC_RPC_ALERT		9	/* RPC alert */

/*
 *	Machine-independent exception behaviors
 */

# define EXCEPTION_DEFAULT		1
/*	Send a catch_exception_raise message including the identity.
 */

# define EXCEPTION_STATE		2
/*	Send a catch_exception_raise_state message including the
 *	thread state.
 */

# define EXCEPTION_STATE_IDENTITY	3
/*	Send a catch_exception_raise_state_identity message including
 *	the thread identity and state.
 */

/*
 * Masks for exception definitions, above
 * bit zero is unused, therefore 1 word = 31 exception types
 */

#define EXC_MASK_BAD_ACCESS		(1 << EXC_BAD_ACCESS)
#define EXC_MASK_BAD_INSTRUCTION	(1 << EXC_BAD_INSTRUCTION)
#define EXC_MASK_ARITHMETIC		(1 << EXC_ARITHMETIC)
#define EXC_MASK_EMULATION		(1 << EXC_EMULATION)
#define EXC_MASK_SOFTWARE		(1 << EXC_SOFTWARE)
#define EXC_MASK_BREAKPOINT		(1 << EXC_BREAKPOINT)
#define EXC_MASK_SYSCALL		(1 << EXC_SYSCALL)
#define EXC_MASK_MACH_SYSCALL		(1 << EXC_MACH_SYSCALL)
#define EXC_MASK_RPC_ALERT		(1 << EXC_RPC_ALERT)

#define EXC_MASK_ALL	(EXC_MASK_BAD_ACCESS |			\
			 EXC_MASK_BAD_INSTRUCTION |		\
			 EXC_MASK_ARITHMETIC |			\
			 EXC_MASK_EMULATION |			\
			 EXC_MASK_SOFTWARE |			\
			 EXC_MASK_BREAKPOINT |			\
			 EXC_MASK_SYSCALL |			\
			 EXC_MASK_MACH_SYSCALL |		\
			 EXC_MASK_RPC_ALERT |			\
			 EXC_MASK_MACHINE)


#define FIRST_EXCEPTION		1	/* ZERO is illegal */

/*
 * Machine independent codes for EXC_SOFTWARE
 * Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix) 
 * 0x10000 - 0x10002 in use for unix signals
 */
#define	EXC_SOFT_SIGNAL		0x10003	/* Unix signal exceptions */

#ifndef	ASSEMBLER
#include <mach/port.h>
#include <mach/thread_status.h>
#include <mach/machine/vm_types.h>
/*
 * Exported types
 */

typedef int			exception_type_t;
typedef	integer_t		exception_data_type_t;
typedef int			exception_behavior_t;
typedef integer_t		*exception_data_t;
typedef	unsigned int		exception_mask_t;
typedef	exception_mask_t	*exception_mask_array_t;
typedef exception_behavior_t	*exception_behavior_array_t;
typedef thread_state_flavor_t	*exception_flavor_array_t;
typedef mach_port_t		*exception_port_array_t;

#endif	/* ASSEMBLER */
#endif	/* _MACH_EXCEPTION_TYPES_H_ */
