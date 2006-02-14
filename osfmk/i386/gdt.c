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
/* CMU_ENDHIST */
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
 * Global descriptor table.
 */
#include <mach/machine.h>
#include <mach/i386/vm_param.h>
#include <kern/thread.h>
#include <i386/cpu_data.h>
#include <i386/mp_desc.h>

#ifdef	MACH_BSD
extern int	trap_unix_syscall(void), trap_mach25_syscall(void),
		trap_machdep_syscall(void), syscall(void);
#endif

struct fake_descriptor gdt[GDTSZ] = {
/* 0x000 */	{ 0, 0, 0, 0 },		/* always NULL */
/* 0x008 */	{ 0,
		  0xfffff,
		  SZ_32|SZ_G,
		  ACC_P|ACC_PL_K|ACC_CODE_R
		},			/* kernel code */
/* 0x010 */	{ 0,
		  0xfffff,
		  SZ_32|SZ_G,
		  ACC_P|ACC_PL_K|ACC_DATA_W
		},			/* kernel data */
/* 0x018 */	{ (unsigned int)ldt,
		  LDTSZ*sizeof(struct fake_descriptor)-1,
		  0,
		  ACC_P|ACC_PL_K|ACC_LDT
		},			/* local descriptor table */
/* 0x020 */	{ (unsigned int)&ktss,
		  sizeof(struct i386_tss)-1,
		  0,
		  ACC_P|ACC_PL_K|ACC_TSS
		},			/* TSS for this processor */
#ifdef	MACH_BSD
/* 0x28 */	{ (unsigned int) &trap_unix_syscall,
		   KERNEL_CS,
		   0,				/* no parameters */
		   ACC_P|ACC_PL_U|ACC_CALL_GATE
		},
/* 0x30 */	{ (unsigned int) &trap_mach25_syscall,
		   KERNEL_CS,
		   0,				/* no parameters */
		   ACC_P|ACC_PL_U|ACC_CALL_GATE
		},
/* 0x38 */	{ (unsigned int) &trap_machdep_syscall,
		   KERNEL_CS,
		   0,				/* no parameters */
		   ACC_P|ACC_PL_U|ACC_CALL_GATE
		},
#else
/* 0x028 */	{ 0, 0, 0, 0 },		/* per-thread LDT */
/* 0x030 */	{ 0, 0, 0, 0 },		/* per-thread TSS for IO bitmap */
/* 0x038 */	{ 0, 0, 0, 0 },
#endif
/* 0x040 */	{ 0, 0, 0, 0 },
/* 0x048 */	{ (unsigned int)&cpu_data_master,
		  sizeof(cpu_data_t)-1,
		  SZ_32,
		  ACC_P|ACC_PL_K|ACC_DATA_W
		},			/* per-CPU current thread address */
#if	MACH_KDB
/* 0x050 */	{ (unsigned int)&dbtss,
		  sizeof(struct i386_tss)-1,
		  0,
		  ACC_P|ACC_PL_K|ACC_TSS
		}			/* TSS for this processor */
#endif	/* MACH_KDB */
};
