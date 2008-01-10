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
 * Kernel task state segment.
 *
 * We don't use the i386 task switch mechanism.  We need a TSS
 * only to hold the kernel stack pointer for the current thread.
 *
 */
#include <i386/tss.h>
#include <i386/seg.h>
#include <mach_kdb.h>

struct i386_tss	master_ktss
	__attribute__ ((section ("__DESC, master_ktss")))
	__attribute__ ((aligned (4096))) = {
	0,				/* back link */
	0,				/* esp0 */
	KERNEL_DS,			/* ss0 */
	0,				/* esp1 */
	0,				/* ss1 */
	0,				/* esp2 */
	0,				/* ss2 */
	0,				/* cr3 */
	0,				/* eip */
	0,				/* eflags */
	0,				/* eax */
	0,				/* ecx */
	0,				/* edx */
	0,				/* ebx */
	0,				/* esp */
	0,				/* ebp */
	0,				/* esi */
	0,				/* edi */
	0,				/* es */
	0,				/* cs */
	0,				/* ss */
	0,				/* ds */
	0,				/* fs */
	0,				/* gs */
	KERNEL_LDT,			/* ldt */
	0,				/* trace_trap */
	0x0FFF				/* IO bitmap offset -
					   beyond end of TSS segment,
					   so no bitmap */
};

/*
 * The transient stack for sysenter.
 * At its top is a 32-bit link to the PCB in legacy mode, 64-bit otherwise.
 * NB: it also must be large enough to contain a interrupt stack frame
 * due to a single-step trace trap at system call entry.
 */
struct sysenter_stack master_sstk
	__attribute__ ((section ("__DESC, master_sstk")))
	__attribute__ ((aligned (16)))  = { {0}, 0 };

#ifdef X86_64
struct x86_64_tss master_ktss64 __attribute__ ((aligned (4096))) = {
	.io_bit_map_offset = 0x0FFF,
};
#endif	/* X86_64 */
 


/*
 * Task structure for double-fault handler:
 */
struct i386_tss	master_dftss
	__attribute__ ((section ("__DESC, master_dftss")))
	__attribute__ ((aligned (4096))) = {
	0,				/* back link */
	(int) &df_task_stack_end - 4,	/* esp0 */
	KERNEL_DS,			/* ss0 */
	0,				/* esp1 */
	0,				/* ss1 */
	0,				/* esp2 */
	0,				/* ss2 */
	0,				/* cr3 */
	(int) &df_task_start,		/* eip */
	0,				/* eflags */
	0,				/* eax */
	0,				/* ecx */
	0,				/* edx */
	0,				/* ebx */
	(int) &df_task_stack_end - 4,	/* esp */
	0,				/* ebp */
	0,				/* esi */
	0,				/* edi */
	KERNEL_DS,			/* es */
	KERNEL_CS,			/* cs */
	KERNEL_DS,			/* ss */
	KERNEL_DS,			/* ds */
	KERNEL_DS,			/* fs */
	CPU_DATA_GS,			/* gs */
	KERNEL_LDT,			/* ldt */
	0,				/* trace_trap */
	0x0FFF				/* IO bitmap offset -
					   beyond end of TSS segment,
					   so no bitmap */
};


/*
 * Task structure for machine_check handler:
 */
struct i386_tss	master_mctss
	__attribute__ ((section ("__DESC, master_mctss")))
	__attribute__ ((aligned (4096))) = {
	0,				/* back link */
	(int) &mc_task_stack_end - 4,	/* esp0 */
	KERNEL_DS,			/* ss0 */
	0,				/* esp1 */
	0,				/* ss1 */
	0,				/* esp2 */
	0,				/* ss2 */
	0,				/* cr3 */
	(int) &mc_task_start,		/* eip */
	0,				/* eflags */
	0,				/* eax */
	0,				/* ecx */
	0,				/* edx */
	0,				/* ebx */
	(int) &mc_task_stack_end - 4,	/* esp */
	0,				/* ebp */
	0,				/* esi */
	0,				/* edi */
	KERNEL_DS,			/* es */
	KERNEL_CS,			/* cs */
	KERNEL_DS,			/* ss */
	KERNEL_DS,			/* ds */
	KERNEL_DS,			/* fs */
	CPU_DATA_GS,			/* gs */
	KERNEL_LDT,			/* ldt */
	0,				/* trace_trap */
	0x0FFF				/* IO bitmap offset -
					   beyond end of TSS segment,
					   so no bitmap */
};

#if	MACH_KDB

struct i386_tss	master_dbtss
	__attribute__ ((section ("__DESC, master_dbtss")))
	__attribute__ ((aligned (4096))) = {
	0,				/* back link */
	0,				/* esp0 */
	KERNEL_DS,			/* ss0 */
	0,				/* esp1 */
	0,				/* ss1 */
	0,				/* esp2 */
	0,				/* ss2 */
	0,				/* cr3 */
	0,				/* eip */
	0,				/* eflags */
	0,				/* eax */
	0,				/* ecx */
	0,				/* edx */
	0,				/* ebx */
	0,				/* esp */
	0,				/* ebp */
	0,				/* esi */
	0,				/* edi */
	KERNEL_DS,			/* es */
	KERNEL_CS,			/* cs */
	KERNEL_DS,			/* ss */
	KERNEL_DS,			/* ds */
	KERNEL_DS,			/* fs */
	KERNEL_DS,			/* gs */
	KERNEL_LDT,			/* ldt */
	0,				/* trace_trap */
	0x0FFF				/* IO bitmap offset -
					   beyond end of TSS segment,
					   so no bitmap */
};

#endif	/* MACH_KDB */
