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
 * Copyright (c) 1990, 1991, 1992, The University of Utah and
 * the Center for Software Science at the University of Utah (CSS).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the Center
 * for Software Science at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSS DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 * 	Utah $Hdr: $
 */

#ifndef	_MACH_PPC_EXCEPTION_H_
#define _MACH_PPC_EXCEPTION_H_


/* STATUS - TODO - this is just transcribed from hp stuff */

#define	EXC_TYPES_COUNT	10	/* incl. illegal exception 0 */

#define EXCEPTION_CODE_MAX 2    /* elements in vector (code+subcode) */
/*
 *	EXC_BAD_INSTRUCTION
 */

#define EXC_PPC_INVALID_SYSCALL	1    /* invalid syscall number */
#define EXC_PPC_UNIPL_INST	2    /* unimplemented instruction */
#define EXC_PPC_PRIVINST	3    /* priviledged instruction */
#define EXC_PPC_PRIVREG		4    /* priviledged register */
#define EXC_PPC_TRACE		5    /* trace/single-step */

/*
 *	EXC_BAD_ACCESS
 *	Note: do not conflict with kern_return_t values returned by vm_fault
 */

#define EXC_PPC_VM_PROT_READ		0x101 /* error reading syscall args */
#define EXC_PPC_BADSPACE		0x102 /* bad space referenced */
#define EXC_PPC_UNALIGNED		0x103 /* unaligned data reference */

/*
 *	EXC_ARITHMETIC
 */

#define EXC_PPC_OVERFLOW		1    /* integer overflow */
#define EXC_PPC_ZERO_DIVIDE		2    /* integer divide by zero */
#define EXC_PPC_FLT_INEXACT		3    /* IEEE inexact exception */
#define EXC_PPC_FLT_ZERO_DIVIDE		4    /* IEEE zero divide */
#define EXC_PPC_FLT_UNDERFLOW		5    /* IEEE floating underflow */
#define EXC_PPC_FLT_OVERFLOW		6    /* IEEE floating overflow */
#define EXC_PPC_FLT_NOT_A_NUMBER	7    /* IEEE not a number */

/*
 * EXC_PPC_NOEMULATION should go away when we add software emulation
 * for floating point. Right now we don't support this.
 */

#define EXC_PPC_NOEMULATION		8	/* no floating point emulation */
#define EXC_PPC_ALTIVECASSIST	9	/* Altivec Denorm Assist */

/*
 *	EXC_SOFTWARE
 */
#define EXC_PPC_TRAP		1		/* Program trap */
#define EXC_PPC_MIGRATE		0x10100		/* Time to bolt */


/*
 *	EXC_BREAKPOINT
 */

#define EXC_PPC_BREAKPOINT		EXC_PPC_TRAP    /* breakpoint trap */

/*
 *	machine dependent exception masks
 */
#define	EXC_MASK_MACHINE	0

#endif	/* _MACH_PPC_EXCEPTION_H_ */
