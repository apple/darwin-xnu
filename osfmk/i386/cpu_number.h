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

/*
 *	Machine-dependent definitions for cpu identification.
 *
 */
#ifndef	_I386_CPU_NUMBER_H_
#define	_I386_CPU_NUMBER_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
extern int	cpu_number(void);

#ifdef MACH_KERNEL_PRIVATE

#include <platforms.h>
#include <cpus.h>

#include <mp_v1_1.h>

#if	MP_V1_1
#include <i386/apic.h>
#include <i386/asm.h>

extern int lapic_id;

extern __inline__ int cpu_number(void)
{
	register int cpu;

	__asm__ volatile ("movl " CC_SYM_PREFIX "lapic_id, %0\n"
			  "	movl 0(%0), %0\n"
			  "	shrl %1, %0\n"
			  "	andl %2, %0"
		    : "=r" (cpu)
		    : "i" (LAPIC_ID_SHIFT), "i" (LAPIC_ID_MASK));

	return(cpu);
}
#else	/* MP_V1_1 */
/*
 * At least one corollary cpu type does not have local memory at all.
 * The only way I found to store the cpu number was in some 386/486
 * system register. cr3 has bits 0, 1, 2 and 5, 6, 7, 8, 9, 10, 11
 * available. Right now we use 0, 1 and 2. So we are limited to 8 cpus.
 * For more cpus, we could use bits 5 - 11 with a shift.
 *
 * Even for other machines, like COMPAQ this is much faster the inb/outb
 * 4 cycles instead of 10 to 30.
 */
#if	defined(__GNUC__)
#if	NCPUS	> 8
#error	cpu_number() definition only works for #cpus <= 8
#else

extern __inline__ int cpu_number(void)
{
	register int cpu;

	__asm__ volatile ("movl %%cr3, %0\n"
		"	andl $0x7, %0"
		    : "=r" (cpu));
	return(cpu);
}
#endif
#endif	/* defined(__GNUC__) */

#endif	/* MP_V1_1 */

#endif	/* MACH_KERNEL_PRIVATE */

#endif  /* __APPLE_API_UNSTABLE */

#endif	/* _I386_CPU_NUMBER_H_ */
