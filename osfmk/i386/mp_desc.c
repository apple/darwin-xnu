/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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


#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <mach/machine.h>
#include <vm/vm_kern.h>

#include <i386/mp_desc.h>
#include <i386/lock.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/pmap.h>

#include <kern/misc_protos.h>

#include <mach_kdb.h>

/*
 * The i386 needs an interrupt stack to keep the PCB stack from being
 * overrun by interrupts.  All interrupt stacks MUST lie at lower addresses
 * than any thread`s kernel stack.
 */

/*
 * First cpu`s interrupt stack.
 */
extern char		intstack[];	/* bottom */
extern char		eintstack[];	/* top */

/*
 * Per-cpu data area pointers.
 * The master cpu (cpu 0) has its data area statically allocated;
 * others are allocated dynamically and this array is updated at runtime.
 */
cpu_data_t	cpu_data_master;
cpu_data_t	*cpu_data_ptr[MAX_CPUS] = { [0] &cpu_data_master };

decl_simple_lock_data(,cpu_lock);	/* protects real_ncpus */
unsigned int	real_ncpus = 1;
unsigned int	max_ncpus = MAX_CPUS;

/*
 * Multiprocessor i386/i486 systems use a separate copy of the
 * GDT, IDT, LDT, and kernel TSS per processor.  The first three
 * are separate to avoid lock contention: the i386 uses locked
 * memory cycles to access the descriptor tables.  The TSS is
 * separate since each processor needs its own kernel stack,
 * and since using a TSS marks it busy.
 */

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

void
mp_desc_init(
	cpu_data_t	*cdp,
	boolean_t	is_boot_cpu)
{
	struct mp_desc_table	*mpt = cdp->cpu_desc_tablep;
	cpu_desc_index_t	*cdt = &cdp->cpu_desc_index;

	if (is_boot_cpu) {
	    /*
	     * Master CPU uses the tables built at boot time.
	     * Just set the TSS and GDT pointers.
	     */
	    cdt->cdi_ktss = &ktss;
#if	MACH_KDB
	    cdt->cdi_dbtss = &dbtss;
#endif	/* MACH_KDB */
	    cdt->cdi_gdt = gdt;
	    cdt->cdi_idt = idt;
	    cdt->cdi_ldt = ldt;

	} else {

	    cdt->cdi_ktss = &mpt->ktss;
	    cdt->cdi_gdt = mpt->gdt;
	    cdt->cdi_idt = mpt->idt;
	    cdt->cdi_ldt = mpt->ldt;

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

#if	MACH_KDB
	    cdt->cdi_dbtss = &dbtss;
	    bcopy((char *)&dbtss,
		  (char *)&mpt->dbtss,
		  sizeof(struct i386_tss));
#endif	/* MACH_KDB */

	    /*
	     * Fix up the entries in the GDT to point to
	     * this LDT and this TSS.
	     */
	    mpt->gdt[sel_idx(KERNEL_LDT)] = ldt_desc_pattern;
	    mpt->gdt[sel_idx(KERNEL_LDT)].offset = (vm_offset_t) mpt->ldt;
	    fix_desc(&mpt->gdt[sel_idx(KERNEL_LDT)], 1);

	    mpt->gdt[sel_idx(KERNEL_TSS)] = tss_desc_pattern;
	    mpt->gdt[sel_idx(KERNEL_TSS)].offset = (vm_offset_t) &mpt->ktss;
	    fix_desc(&mpt->gdt[sel_idx(KERNEL_TSS)], 1);

	    mpt->gdt[sel_idx(CPU_DATA_GS)] = cpudata_desc_pattern;
	    mpt->gdt[sel_idx(CPU_DATA_GS)].offset = (vm_offset_t) cdp;
	    fix_desc(&mpt->gdt[sel_idx(CPU_DATA_GS)], 1);

#if	MACH_KDB
	    mpt->gdt[sel_idx(DEBUG_TSS)] = tss_desc_pattern;
	    mpt->gdt[sel_idx(DEBUG_TSS)].offset = (vm_offset_t) &mpt->dbtss;
	    fix_desc(&mpt->gdt[sel_idx(DEBUG_TSS)], 1);

	    mpt->dbtss.esp0 = (int)(db_task_stack_store +
		    (INTSTACK_SIZE * (cpu + 1)) - sizeof (natural_t));
	    mpt->dbtss.esp = mpt->dbtss.esp0;
	    mpt->dbtss.eip = (int)&db_task_start;
#endif	/* MACH_KDB */

	    mpt->ktss.ss0 = KERNEL_DS;
	    mpt->ktss.io_bit_map_offset = 0x0FFF;	/* no IO bitmap */
	}
}

cpu_data_t *
cpu_data_alloc(boolean_t is_boot_cpu)
{
	int		ret;
	cpu_data_t	*cdp;

	if (is_boot_cpu) {
		assert(real_ncpus == 1);
		simple_lock_init(&cpu_lock, 0);
		cdp = &cpu_data_master;
		if (cdp->cpu_processor == NULL) {
			cdp->cpu_processor = cpu_processor_alloc(TRUE);
			cdp->cpu_pmap = pmap_cpu_alloc(TRUE);
			cdp->cpu_this = cdp;
			cdp->cpu_int_stack_top = (vm_offset_t) eintstack;
			mp_desc_init(cdp, TRUE);
		}
		return cdp;
	}

	/* Check count before making allocations */
	if (real_ncpus >= max_ncpus)
		return NULL;

	/*
	 * Allocate per-cpu data:
	 */
	ret = kmem_alloc(kernel_map, 
			 (vm_offset_t *) &cdp, sizeof(cpu_data_t));
	if (ret != KERN_SUCCESS) {
		printf("cpu_data_alloc() failed, ret=%d\n", ret);
		goto abort;
	}
	bzero((void*) cdp, sizeof(cpu_data_t));
	cdp->cpu_this = cdp;

	/*
	 * Allocate interrupt stack:
	 */
	ret = kmem_alloc(kernel_map, 
			 (vm_offset_t *) &cdp->cpu_int_stack_top,
			 INTSTACK_SIZE);
	if (ret != KERN_SUCCESS) {
		printf("cpu_data_alloc() int stack failed, ret=%d\n", ret);
		goto abort;
	}
	bzero((void*) cdp->cpu_int_stack_top, INTSTACK_SIZE);
	cdp->cpu_int_stack_top += INTSTACK_SIZE;

	/*
	 * Allocate descriptor table:
	 */
	ret = kmem_alloc(kernel_map, 
			 (vm_offset_t *) &cdp->cpu_desc_tablep,
			 sizeof(struct mp_desc_table));
	if (ret != KERN_SUCCESS) {
		printf("cpu_data_alloc() desc_table failed, ret=%d\n", ret);
		goto abort;
	}

	simple_lock(&cpu_lock);
	if (real_ncpus >= max_ncpus) {
		simple_unlock(&cpu_lock);
		goto abort;
	}
	cpu_data_ptr[real_ncpus] = cdp;
	cdp->cpu_number = real_ncpus;
	real_ncpus++;
	simple_unlock(&cpu_lock);
	
	kprintf("cpu_data_alloc(%d) 0x%x desc_table: 0x%x "
		"int_stack: 0x%x-0x%x\n",
		cdp->cpu_number, cdp, cdp->cpu_desc_tablep,
		cdp->cpu_int_stack_top - INTSTACK_SIZE, cdp->cpu_int_stack_top);

	return cdp;

abort:
	if (cdp) {
		if (cdp->cpu_desc_tablep)
			kfree((void *) cdp->cpu_desc_tablep,
				sizeof(*cdp->cpu_desc_tablep));
		if (cdp->cpu_int_stack_top)
			kfree((void *) (cdp->cpu_int_stack_top - INTSTACK_SIZE),
				INTSTACK_SIZE);
		kfree((void *) cdp, sizeof(*cdp));
	}
	return NULL;
}

boolean_t
valid_user_segment_selectors(uint16_t cs,
			     uint16_t ss,
			     uint16_t ds,
			     uint16_t es,
			     uint16_t fs,
			     uint16_t gs)
{	
	return valid_user_code_selector(cs)  &&
	       valid_user_stack_selector(ss) &&
	       valid_user_data_selector(ds)  &&
	       valid_user_data_selector(es)  &&
	       valid_user_data_selector(fs)  &&
	       valid_user_data_selector(gs);
}

