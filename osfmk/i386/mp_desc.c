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

#include <cpus.h>

#if	NCPUS > 1

#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <mach/machine.h>
#include <vm/vm_kern.h>

#include <i386/mp_desc.h>
#include <i386/lock.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>

#include <kern/misc_protos.h>

#include <mach_kdb.h>

/*
 * The i386 needs an interrupt stack to keep the PCB stack from being
 * overrun by interrupts.  All interrupt stacks MUST lie at lower addresses
 * than any thread`s kernel stack.
 */

/*
 * Addresses of bottom and top of interrupt stacks.
 */
vm_offset_t	interrupt_stack[NCPUS];
vm_offset_t	int_stack_top[NCPUS];

/*
 * Barrier address.
 */
vm_offset_t	int_stack_high;

/*
 * First cpu`s interrupt stack.
 */
extern char		intstack[];	/* bottom */
extern char		eintstack[];	/* top */

/*
 * We allocate interrupt stacks from physical memory.
 */
extern
vm_offset_t	avail_start;

/*
 * Multiprocessor i386/i486 systems use a separate copy of the
 * GDT, IDT, LDT, and kernel TSS per processor.  The first three
 * are separate to avoid lock contention: the i386 uses locked
 * memory cycles to access the descriptor tables.  The TSS is
 * separate since each processor needs its own kernel stack,
 * and since using a TSS marks it busy.
 */

/*
 * Allocated descriptor tables.
 */
struct mp_desc_table	*mp_desc_table[NCPUS] = { 0 };

/*
 * Pointer to TSS for access in load_context.
 */
struct i386_tss		*mp_ktss[NCPUS] = { 0 };

#if	MACH_KDB
/*
 * Pointer to TSS for debugger use.
 */
struct i386_tss		*mp_dbtss[NCPUS] = { 0 };
#endif	/* MACH_KDB */

/*
 * Pointer to GDT to reset the KTSS busy bit.
 */
struct fake_descriptor	*mp_gdt[NCPUS] = { 0 };
struct fake_descriptor	*mp_idt[NCPUS] = { 0 };
struct fake_descriptor	*mp_ldt[NCPUS] = { 0 };

/*
 * Allocate and initialize the per-processor descriptor tables.
 */

struct fake_descriptor ldt_desc_pattern = {
	(unsigned int) 0,
	LDTSZ * sizeof(struct fake_descriptor) - 1,
	0,
	ACC_P|ACC_PL_K|ACC_LDT
};
struct fake_descriptor tss_desc_pattern = {
	(unsigned int) 0,
	sizeof(struct i386_tss),
	0,
	ACC_P|ACC_PL_K|ACC_TSS
};

struct fake_descriptor cpudata_desc_pattern = {
	(unsigned int) 0,
	sizeof(cpu_data_t)-1,
	SZ_32,
	ACC_P|ACC_PL_K|ACC_DATA_W
};

struct mp_desc_table *
mp_desc_init(
	int	mycpu)
{
	register struct mp_desc_table *mpt;

	if (mycpu == master_cpu) {
	    /*
	     * Master CPU uses the tables built at boot time.
	     * Just set the TSS and GDT pointers.
	     */
	    mp_ktss[mycpu] = &ktss;
#if	MACH_KDB
	    mp_dbtss[mycpu] = &dbtss;
#endif	/* MACH_KDB */
	    mp_gdt[mycpu] = gdt;
	    mp_idt[mycpu] = idt;
	    mp_ldt[mycpu] = ldt;
	    return 0;
	}
	else {
	    mpt = mp_desc_table[mycpu];
	    mp_ktss[mycpu] = &mpt->ktss;
	    mp_gdt[mycpu] = mpt->gdt;
	    mp_idt[mycpu] = mpt->idt;
	    mp_ldt[mycpu] = mpt->ldt;

	    /*
	     * Copy the tables
	     */
	    bcopy((char *)idt,
		  (char *)mpt->idt,
		  sizeof(idt));
	    bcopy((char *)gdt,
		  (char *)mpt->gdt,
		  sizeof(gdt));
	    bcopy((char *)ldt,
		  (char *)mpt->ldt,
		  sizeof(ldt));
	    bzero((char *)&mpt->ktss,
		  sizeof(struct i386_tss));
#if 0
	    bzero((char *)&cpu_data[mycpu],
		  sizeof(cpu_data_t));
#endif
	    /* I am myself */
	    cpu_data[mycpu].cpu_number = mycpu;

#if	MACH_KDB
	    mp_dbtss[mycpu] = &mpt->dbtss;
	    bcopy((char *)&dbtss,
		  (char *)&mpt->dbtss,
		  sizeof(struct i386_tss));
#endif	/* MACH_KDB */

	    /*
	     * Fix up the entries in the GDT to point to
	     * this LDT and this TSS.
	     */
	    mpt->gdt[sel_idx(KERNEL_LDT)] = ldt_desc_pattern;
	    mpt->gdt[sel_idx(KERNEL_LDT)].offset =
		LINEAR_KERNEL_ADDRESS + (unsigned int) mpt->ldt;
	    fix_desc(&mpt->gdt[sel_idx(KERNEL_LDT)], 1);

	    mpt->gdt[sel_idx(KERNEL_TSS)] = tss_desc_pattern;
	    mpt->gdt[sel_idx(KERNEL_TSS)].offset =
		LINEAR_KERNEL_ADDRESS + (unsigned int) &mpt->ktss;
	    fix_desc(&mpt->gdt[sel_idx(KERNEL_TSS)], 1);

	    mpt->gdt[sel_idx(CPU_DATA)] = cpudata_desc_pattern;
	    mpt->gdt[sel_idx(CPU_DATA)].offset =
	    	LINEAR_KERNEL_ADDRESS + (unsigned int) &cpu_data[mycpu];
	    fix_desc(&mpt->gdt[sel_idx(CPU_DATA)], 1);

#if	MACH_KDB
	    mpt->gdt[sel_idx(DEBUG_TSS)] = tss_desc_pattern;
	    mpt->gdt[sel_idx(DEBUG_TSS)].offset =
		    LINEAR_KERNEL_ADDRESS + (unsigned int) &mpt->dbtss;
	    fix_desc(&mpt->gdt[sel_idx(DEBUG_TSS)], 1);

	    mpt->dbtss.esp0 = (int)(db_task_stack_store +
		    (INTSTACK_SIZE * (mycpu + 1)) - sizeof (natural_t));
	    mpt->dbtss.esp = mpt->dbtss.esp0;
	    mpt->dbtss.eip = (int)&db_task_start;
#endif	/* MACH_KDB */

	    mpt->ktss.ss0 = KERNEL_DS;
	    mpt->ktss.io_bit_map_offset = 0x0FFF;	/* no IO bitmap */

	    return mpt;
	}
}

/*
 * Called after all CPUs have been found, but before the VM system
 * is running.  The machine array must show which CPUs exist.
 */
void
interrupt_stack_alloc(void)
{
	register int		i;
	int			cpu_count;
	vm_offset_t		stack_start;
	struct mp_desc_table 	*mpt;

	/*
	 * Number of CPUs possible.
	 */
	cpu_count = wncpu;

	/*
	 * Allocate an interrupt stack for each CPU except for
	 * the master CPU (which uses the bootstrap stack)
	 */
	stack_start = phystokv(avail_start);
	avail_start = round_page(avail_start + INTSTACK_SIZE*(cpu_count-1));
	bzero((char *)stack_start, INTSTACK_SIZE*(cpu_count-1));

	/*
	 * Set up pointers to the top of the interrupt stack.
	 */
	for (i = 0; i < cpu_count; i++) {
	    if (i == master_cpu) {
		interrupt_stack[i] = (vm_offset_t) intstack;
		int_stack_top[i]   = (vm_offset_t) eintstack;
	    }
	    else {
		interrupt_stack[i] = stack_start;
		int_stack_top[i]   = stack_start + INTSTACK_SIZE;

		stack_start += INTSTACK_SIZE;
	    }
	}

	/*
	 * Allocate descriptor tables for each CPU except for
	 * the master CPU (which already has them initialized)
	 */

	mpt = (struct mp_desc_table *) phystokv(avail_start);
	avail_start = round_page((vm_offset_t)avail_start +
				 sizeof(struct mp_desc_table)*(cpu_count-1));
	for (i = 0; i < cpu_count; i++)
	    if (i != master_cpu)
		mp_desc_table[i] = mpt++;


	/*
	 * Set up the barrier address.  All thread stacks MUST
	 * be above this address.
	 */
	/*
	 * intstack is at higher addess than stack_start for AT mps
	 * so int_stack_high must point at eintstack.
	 * XXX
	 * But what happens if a kernel stack gets allocated below
	 * 1 Meg ? Probably never happens, there is only 640 K available
	 * There.
	 */
	int_stack_high = (vm_offset_t) eintstack;
}

#endif /* NCPUS > 1 */
