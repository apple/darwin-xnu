/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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

#include <mach_kdb.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

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
typedef struct cpu_desc_table {
	struct fake_descriptor	idt[IDTSZ] __attribute__ ((aligned (16)));
	struct fake_descriptor	gdt[GDTSZ] __attribute__ ((aligned (16)));
	struct i386_tss		ktss       __attribute__ ((aligned (16)));
	struct i386_tss		dbtss      __attribute__ ((aligned (16)));
	struct sysenter_stack	sstk;
} cpu_desc_table_t;

typedef struct cpu_desc_table64 {
	struct fake_descriptor64 idt[IDTSZ]      __attribute__ ((aligned (16)));
	struct fake_descriptor	gdt[GDTSZ]       __attribute__ ((aligned (16)));
	struct x86_64_tss	ktss             __attribute__ ((aligned (16)));
	struct sysenter_stack	sstk	         __attribute__ ((aligned (16)));
	uint8_t			dfstk[PAGE_SIZE] __attribute__ ((aligned (16)));
} cpu_desc_table64_t;

#define	current_gdt()	(current_cpu_datap()->cpu_desc_index.cdi_gdt.ptr)
#define	current_idt()	(current_cpu_datap()->cpu_desc_index.cdi_idt.ptr)
#define	current_ldt()	(current_cpu_datap()->cpu_desc_index.cdi_ldt)
#define	current_ktss()	(current_cpu_datap()->cpu_desc_index.cdi_ktss)
#define	current_dbtss()	(current_cpu_datap()->cpu_desc_index.cdi_dbtss)
#define	current_sstk()	(current_cpu_datap()->cpu_desc_index.cdi_sstk)

#define	current_ktss64() ((struct x86_64_tss *) current_ktss())
#define	current_sstk64() ((addr64_t *) current_sstk())

#define	gdt_desc_p(sel) \
	(&((struct real_descriptor *)current_gdt())[sel_idx(sel)])
#define	ldt_desc_p(sel) \
	(&((struct real_descriptor *)current_ldt())[sel_idx(sel)])

extern void	cpu_mode_init(cpu_data_t *cdp);

extern void	cpu_desc_init(cpu_data_t *cdp);
extern void	cpu_desc_init64(cpu_data_t *cdp);
extern void	cpu_desc_load(cpu_data_t *cdp);
extern void	cpu_desc_load64(cpu_data_t *cdp);

extern boolean_t
valid_user_data_selector(uint16_t selector);

extern boolean_t
valid_user_code_selector(uint16_t selector);

extern boolean_t
valid_user_stack_selector(uint16_t selector);

extern boolean_t
valid_user_segment_selectors(uint16_t cs,
                             uint16_t ss,
                             uint16_t ds,
                             uint16_t es,
                             uint16_t fs,
                             uint16_t gs);

__END_DECLS

#endif	/* _X86_64_MP_DESC_H_ */
