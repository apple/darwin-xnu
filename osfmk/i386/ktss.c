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
 * XXX multiprocessor??
 */
#include <i386/tss.h>
#include <i386/seg.h>
#include <mach_kdb.h>

struct i386_tss	ktss = {
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

#if	MACH_KDB

struct i386_tss	dbtss = {
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
