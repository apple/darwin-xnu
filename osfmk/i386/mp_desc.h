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

#ifndef	_I386_MP_DESC_H_
#define	_I386_MP_DESC_H_

#include <cpus.h>
#include <mach_kdb.h>

/*
 * Multiprocessor i386/i486 systems use a separate copy of the
 * GDT, IDT, LDT, and kernel TSS per processor.  The first three
 * are separate to avoid lock contention: the i386 uses locked
 * memory cycles to access the descriptor tables.  The TSS is
 * separate since each processor needs its own kernel stack,
 * and since using a TSS marks it busy.
 */

#include <i386/seg.h>
#include <i386/tss.h>

/*
 * The descriptor tables are together in a structure
 * allocated one per processor (except for the boot processor).
 * Note that dbtss could be conditionalized on MACH_KDB, but
 * doing so increases misconfiguration risk.
 */
struct mp_desc_table {
	struct fake_descriptor	idt[IDTSZ];	/* IDT */
	struct fake_descriptor	gdt[GDTSZ];	/* GDT */
	struct fake_descriptor	ldt[LDTSZ];	/* LDT */
	struct i386_tss		ktss;
	struct i386_tss		dbtss;
};

/*
 * They are pointed to by a per-processor array.
 */
extern struct mp_desc_table	*mp_desc_table[NCPUS];

/*
 * The kernel TSS gets its own pointer.
 */
extern struct i386_tss		*mp_ktss[NCPUS];
#if	MACH_KDB
extern struct i386_tss		*mp_dbtss[NCPUS];
#endif	/* MACH_KDB */

/*
 * So does the GDT and IDT.
 */
extern struct fake_descriptor	*mp_gdt[NCPUS];
extern struct fake_descriptor	*mp_idt[NCPUS];


/*
 * Each CPU calls this routine to set up its descriptor tables.
 */

extern struct mp_desc_table *	mp_desc_init(
					int		cpu);
extern void			interrupt_stack_alloc(void);

#endif	/* _I386_MP_DESC_H_ */
