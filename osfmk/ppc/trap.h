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

#ifndef	_PPC_TRAP_H_
#define	_PPC_TRAP_H_

/* maximum number of arguments to a syscall trap */
#define NARGS	12
/* Size to reserve in frame for arguments - first 8 are in registers */
#define ARG_SIZE FM_ALIGN((NARGS-8)*4)


/*
 * Hardware exception vectors for powerpc are in exception.h
 */

#ifndef	ASSEMBLER

#include <mach/thread_status.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <ppc/thread.h>

extern void			doexception(int exc, int code, int sub);

extern void			thread_exception_return(void);

extern struct savearea*	trap(int trapno,
				     struct savearea *ss,
				     unsigned int dsisr,
				     addr64_t dar);

typedef kern_return_t (*perfTrap)(int trapno, struct savearea *ss, 
	unsigned int dsisr, addr64_t dar);

extern perfTrap perfTrapHook;
extern perfTrap perfIntHook;

extern struct savearea* interrupt(int intno,
					 struct savearea *ss,
					 unsigned int dsisr,
					 unsigned int dar);

extern int			syscall_error(int exception,
					      int code,
					      int subcode,
					      struct savearea *ss);


#endif	/* ASSEMBLER */

#endif	/* _PPC_TRAP_H_ */
