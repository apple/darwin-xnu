/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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


#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <i386/mp_desc.h>
#include <i386/lock.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/pmap.h>
#include <i386/cpu_threads.h>

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
extern uint32_t		low_intstack[];	/* bottom */
extern uint32_t		low_eintstack[];	/* top */

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

extern void *hi_remap_text;
#define HI_TEXT(lo_text)	\
	(((uint32_t)&lo_text - (uint32_t)&hi_remap_text) + HIGH_MEM_BASE)

extern void	hi_sysenter(void);
extern void	hi64_sysenter(void);
extern void	hi64_syscall(void);


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
	LDTSZ_MIN * sizeof(struct fake_descriptor) - 1,
	0,
	ACC_P|ACC_PL_K|ACC_LDT
};

struct fake_descriptor tss_desc_pattern = {
	(unsigned int) 0,
	sizeof(struct i386_tss) - 1,
	0,
	ACC_P|ACC_PL_K|ACC_TSS
};

struct fake_descriptor cpudata_desc_pattern = {
	(unsigned int) 0,
	sizeof(cpu_data_t)-1,
	SZ_32,
	ACC_P|ACC_PL_K|ACC_DATA_W
};

struct fake_descriptor userwindow_desc_pattern = {
	(unsigned int) 0,
	((NBPDE * NCOPY_WINDOWS) / PAGE_SIZE) - 1,
	SZ_32 | SZ_G,
	ACC_P|ACC_PL_U|ACC_DATA_W
};

struct fake_descriptor physwindow_desc_pattern = {
	(unsigned int) 0,
	PAGE_SIZE - 1,
	SZ_32,
	ACC_P|ACC_PL_K|ACC_DATA_W
};

/*
 * This is the expanded, 64-bit variant of the kernel LDT descriptor.
 * When switching to 64-bit mode this replaces KERNEL_LDT entry
 * and the following empty slot. This enables the LDT to be referenced
 * in the uber-space remapping window on the kernel.
 */
struct fake_descriptor64 kernel_ldt_desc64 = {
	FAKE_UBER64(&master_ldt),
	LDTSZ_MIN*sizeof(struct fake_descriptor)-1,
	0,
	ACC_P|ACC_PL_K|ACC_LDT,
	0
};

/*
 * This is the expanded, 64-bit variant of the kernel TSS descriptor.
 * It is follows pattern of the KERNEL_LDT.
 */
struct fake_descriptor64 kernel_tss_desc64 = {
	FAKE_UBER64(&master_ktss64),
	sizeof(struct x86_64_tss)-1,
	0,
	ACC_P|ACC_PL_K|ACC_TSS,
	0
};

void
cpu_desc_init(
	cpu_data_t	*cdp,
	boolean_t	is_boot_cpu)
{
	cpu_desc_table_t	*cdt = cdp->cpu_desc_tablep;
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

	if (is_boot_cpu) {
	    /*
	     * Master CPU uses the tables built at boot time.
	     * Just set the index pointers to the high shared-mapping space.
	     * Note that the sysenter stack uses empty space above the ktss
	     * in the HIGH_FIXED_KTSS page. In this case we don't map the
	     * the real master_sstk in low memory.
	     */
	    cdi->cdi_ktss = (struct i386_tss *)
				pmap_index_to_virt(HIGH_FIXED_KTSS) ;
	    cdi->cdi_sstk  = (vm_offset_t) (cdi->cdi_ktss + 1) +
				(vm_offset_t) &master_sstk.top -
				(vm_offset_t) &master_sstk;
#if	MACH_KDB
	    cdi->cdi_dbtss = (struct i386_tss *)
				pmap_index_to_virt(HIGH_FIXED_DBTSS);
#endif	/* MACH_KDB */
	    cdi->cdi_gdt = (struct fake_descriptor *)
				pmap_index_to_virt(HIGH_FIXED_GDT);
	    cdi->cdi_idt = (struct fake_descriptor *)
				pmap_index_to_virt(HIGH_FIXED_IDT);
	    cdi->cdi_ldt = (struct fake_descriptor *)
				pmap_index_to_virt(HIGH_FIXED_LDT_BEGIN);

	} else {

	    vm_offset_t	cpu_hi_desc;

	    cpu_hi_desc = pmap_cpu_high_shared_remap(cdp->cpu_number,
						     HIGH_CPU_DESC,
						     (vm_offset_t) cdt, 1);

	    /*
	     * Per-cpu GDT, IDT, LDT, KTSS descriptors are allocated in one
	     * block (cpu_desc_table) and double-mapped into high shared space
	     * in one page window.
	     * Also, a transient stack for the fast sysenter path. The top of
	     * which is set at context switch time to point to the PCB using
	     * the high address.
	     */
	    cdi->cdi_gdt  = (struct fake_descriptor *) (cpu_hi_desc +
				offsetof(cpu_desc_table_t, gdt[0]));
	    cdi->cdi_idt  = (struct fake_descriptor *) (cpu_hi_desc +
				offsetof(cpu_desc_table_t, idt[0]));
	    cdi->cdi_ktss = (struct i386_tss *) (cpu_hi_desc +
				offsetof(cpu_desc_table_t, ktss));
	    cdi->cdi_sstk = cpu_hi_desc +
				offsetof(cpu_desc_table_t, sstk.top);
				
	    /*
	     * LDT descriptors are mapped into a seperate area.
	     */
	    cdi->cdi_ldt  = (struct fake_descriptor *)
				pmap_cpu_high_shared_remap(
				    cdp->cpu_number,
				    HIGH_CPU_LDT_BEGIN,
				    (vm_offset_t) cdp->cpu_ldtp,
				    HIGH_CPU_LDT_END - HIGH_CPU_LDT_BEGIN + 1);

	    /*
	     * Copy the tables
	     */
	    bcopy((char *)master_idt,
		  (char *)cdt->idt,
		  sizeof(master_idt));
	    bcopy((char *)master_gdt,
		  (char *)cdt->gdt,
		  sizeof(master_gdt));
	    bcopy((char *)master_ldt,
		  (char *)cdp->cpu_ldtp,
		  sizeof(master_ldt));
	    bzero((char *)&cdt->ktss,
		  sizeof(struct i386_tss));

#if	MACH_KDB
	    cdi->cdi_dbtss = (struct i386_tss *) (cpu_hi_desc +
				offsetof(cpu_desc_table_t, dbtss));
	    bcopy((char *)&master_dbtss,
		  (char *)&cdt->dbtss,
		  sizeof(struct i386_tss));
#endif	/* MACH_KDB */

	    /*
	     * Fix up the entries in the GDT to point to
	     * this LDT and this TSS.
	     */
	    cdt->gdt[sel_idx(KERNEL_LDT)] = ldt_desc_pattern;
	    cdt->gdt[sel_idx(KERNEL_LDT)].offset = (vm_offset_t) cdi->cdi_ldt;
	    fix_desc(&cdt->gdt[sel_idx(KERNEL_LDT)], 1);

	    cdt->gdt[sel_idx(USER_LDT)] = ldt_desc_pattern;
	    cdt->gdt[sel_idx(USER_LDT)].offset = (vm_offset_t) cdi->cdi_ldt;
	    fix_desc(&cdt->gdt[sel_idx(USER_LDT)], 1);

	    cdt->gdt[sel_idx(KERNEL_TSS)] = tss_desc_pattern;
	    cdt->gdt[sel_idx(KERNEL_TSS)].offset = (vm_offset_t) cdi->cdi_ktss;
	    fix_desc(&cdt->gdt[sel_idx(KERNEL_TSS)], 1);

	    cdt->gdt[sel_idx(CPU_DATA_GS)] = cpudata_desc_pattern;
	    cdt->gdt[sel_idx(CPU_DATA_GS)].offset = (vm_offset_t) cdp;
	    fix_desc(&cdt->gdt[sel_idx(CPU_DATA_GS)], 1);

#if	MACH_KDB
	    cdt->gdt[sel_idx(DEBUG_TSS)] = tss_desc_pattern;
	    cdt->gdt[sel_idx(DEBUG_TSS)].offset = (vm_offset_t) cdi->cdi_dbtss;
	    fix_desc(&cdt->gdt[sel_idx(DEBUG_TSS)], 1);

	    cdt->dbtss.esp0 = (int)(db_task_stack_store +
		    (INTSTACK_SIZE * (cdp->cpu_number)) - sizeof (natural_t));
	    cdt->dbtss.esp = cdt->dbtss.esp0;
	    cdt->dbtss.eip = (int)&db_task_start;
#endif	/* MACH_KDB */

	    cdt->ktss.ss0 = KERNEL_DS;
	    cdt->ktss.io_bit_map_offset = 0x0FFF;	/* no IO bitmap */

	    cpu_window_init(cdp->cpu_number);

	}

}

void
cpu_desc_init64(
	cpu_data_t	*cdp,
	boolean_t	is_boot_cpu)
{
	cpu_desc_table64_t	*cdt = (cpu_desc_table64_t *)
					cdp->cpu_desc_tablep;
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

	if (is_boot_cpu) {
	    /*
	     * Master CPU uses the tables built at boot time.
	     * Just set the index pointers to the low memory space.
	     * Note that in 64-bit mode these are addressed in the
	     * double-mapped window (uber-space).
	     */
	    cdi->cdi_ktss = (struct i386_tss *) &master_ktss64;
	    cdi->cdi_sstk = (vm_offset_t) &master_sstk.top;
	    cdi->cdi_gdt  = master_gdt;
	    cdi->cdi_idt  = (struct fake_descriptor *) &master_idt64;
	    cdi->cdi_ldt  = (struct fake_descriptor *) &master_ldt;

	    /* Replace the expanded LDT and TSS slots in the GDT: */
	    *(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_LDT)] =
		kernel_ldt_desc64;
	    *(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_TSS)] =
		kernel_tss_desc64;

	    /*
	     * Fix up the expanded descriptors for 64-bit.
	     */
	    fix_desc64((void *) &master_idt64, IDTSZ);
	    fix_desc64((void *) &master_gdt[sel_idx(KERNEL_LDT)], 1);
	    fix_desc64((void *) &master_gdt[sel_idx(KERNEL_TSS)], 1);

	    /*
	     * Set the double-fault stack as IST1 in the 64-bit TSS 
	     */
	    master_ktss64.ist1 = UBER64(df_task_stack_end);

	} else {
	    /*
	     * Per-cpu GDT, IDT, KTSS descriptors are allocated in kernel 
	     * heap (cpu_desc_table) and double-mapped in uber-space (over 4GB).
	     * LDT descriptors are mapped into a separate area.
	     */
	    cdi->cdi_gdt  = cdt->gdt;
	    cdi->cdi_idt  = (struct fake_descriptor *) cdt->idt;
	    cdi->cdi_ktss = (struct i386_tss *) &cdt->ktss;
	    cdi->cdi_sstk = (vm_offset_t) &cdt->sstk.top;
	    cdi->cdi_ldt  = cdp->cpu_ldtp;

	    /*
	     * Copy the tables
	     */
	    bcopy((char *)master_idt64,
		  (char *)cdt->idt,
		  sizeof(master_idt64));
	    bcopy((char *)master_gdt,
		  (char *)cdt->gdt,
		  sizeof(master_gdt));
	    bcopy((char *)master_ldt,
		  (char *)cdp->cpu_ldtp,
		  sizeof(master_ldt));
	    bcopy((char *)&master_ktss64,
		  (char *)&cdt->ktss,
		  sizeof(struct x86_64_tss));

	    /*
	     * Fix up the entries in the GDT to point to
	     * this LDT and this TSS.
	     */
	    kernel_ldt_desc64.offset[0] = (vm_offset_t) cdi->cdi_ldt;
	    *(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_LDT)] =
	    		kernel_ldt_desc64;
	    fix_desc64(&cdt->gdt[sel_idx(KERNEL_LDT)], 1);

	    kernel_ldt_desc64.offset[0] = (vm_offset_t) cdi->cdi_ldt;
	    *(struct fake_descriptor64 *) &cdt->gdt[sel_idx(USER_LDT)] =
	    		kernel_ldt_desc64;
	    fix_desc64(&cdt->gdt[sel_idx(USER_LDT)], 1);

	    kernel_tss_desc64.offset[0] = (vm_offset_t) cdi->cdi_ktss;
	    *(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_TSS)] =
	    		kernel_tss_desc64;
	    fix_desc64(&cdt->gdt[sel_idx(KERNEL_TSS)], 1);

	    cdt->gdt[sel_idx(CPU_DATA_GS)] = cpudata_desc_pattern;
	    cdt->gdt[sel_idx(CPU_DATA_GS)].offset = (vm_offset_t) cdp;
	    fix_desc(&cdt->gdt[sel_idx(CPU_DATA_GS)], 1);

	    /* Set double-fault stack as IST1 */
	    cdt->ktss.ist1 = UBER64(cdt->dfstk + sizeof(cdt->dfstk));

	    /*
	     * Allocate copyio windows.
	     */
	    cpu_window_init(cdp->cpu_number);

	}

	/* Require that the top of the sysenter stack is 16-byte aligned */
	if ((cdi->cdi_sstk % 16) != 0)
		panic("cpu_desc_init64() sysenter stack not 16-byte aligned");
}

/*
 * Set MSRs for sysenter/sysexit for 64-bit.
 */
void
fast_syscall_init64(void)
{
	wrmsr64(MSR_IA32_SYSENTER_CS, SYSENTER_CS); 
	wrmsr64(MSR_IA32_SYSENTER_EIP, UBER64(hi64_sysenter));
	wrmsr64(MSR_IA32_SYSENTER_ESP, UBER64(current_sstk()));

	/* Enable syscall/sysret */
	wrmsr64(MSR_IA32_EFER, rdmsr64(MSR_IA32_EFER) | MSR_IA32_EFER_SCE);

	/*
	 * MSRs for 64-bit syscall/sysret
	 * Note USER_CS because sysret uses this + 16 when returning to
	 * 64-bit code.
	 */
	wrmsr64(MSR_IA32_LSTAR, UBER64(hi64_syscall));
	wrmsr64(MSR_IA32_STAR, (((uint64_t)USER_CS)     << 48) |
			       (((uint64_t)KERNEL64_CS) << 32));
	/*
	 * Emulate eflags cleared by sysenter but note that
	 * we also clear the trace trap to avoid the complications
	 * of single-stepping into a syscall. We also clear
	 * the nested task bit to avoid a spurious "task switch"
	 * on IRET.
	 */
	wrmsr64(MSR_IA32_FMASK, EFL_DF|EFL_IF|EFL_TF|EFL_NT);

	/*
	 * Set the Kermel GS base MSR to point to per-cpu data in uber-space.
	 * The uber-space handler (hi64_syscall) uses the swapgs instruction.
	 */
	wrmsr64(MSR_IA32_KERNEL_GS_BASE, UBER64(current_cpu_datap()));
	kprintf("fast_syscall_init64() KERNEL_GS_BASE=0x%016llx\n",
		rdmsr64(MSR_IA32_KERNEL_GS_BASE));
}

/*
 * Set MSRs for sysenter/sysexit
 */
void
fast_syscall_init(void)
{
	wrmsr(MSR_IA32_SYSENTER_CS, SYSENTER_CS, 0); 
	wrmsr(MSR_IA32_SYSENTER_EIP, HI_TEXT(hi_sysenter), 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, current_sstk(), 0);
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
			cdp->cpu_is64bit = FALSE;
			cdp->cpu_int_stack_top = (vm_offset_t) low_eintstack;
			cpu_desc_init(cdp, TRUE);
			fast_syscall_init();
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

	/* Propagate mode */
	cdp->cpu_is64bit = cpu_mode_is64bit();

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
	 * Size depends on cpu mode.
	 */
	ret = kmem_alloc(kernel_map, 
			 (vm_offset_t *) &cdp->cpu_desc_tablep,
			 cdp->cpu_is64bit ? sizeof(cpu_desc_table64_t)
					  : sizeof(cpu_desc_table_t));
	if (ret != KERN_SUCCESS) {
		printf("cpu_data_alloc() desc_table failed, ret=%d\n", ret);
		goto abort;
	}

	/*
	 * Allocate LDT
	 */
	ret = kmem_alloc(kernel_map, 
			 (vm_offset_t *) &cdp->cpu_ldtp,
			 sizeof(struct real_descriptor) * LDTSZ);
	if (ret != KERN_SUCCESS) {
		printf("cpu_data_alloc() ldt failed, ret=%d\n", ret);
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
		"ldt: 0x%x "
		"int_stack: 0x%x-0x%x\n",
		cdp->cpu_number, cdp, cdp->cpu_desc_tablep, cdp->cpu_ldtp,
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


static vm_offset_t user_window_base = 0;
static vm_offset_t phys_window_base = 0;

void
cpu_window_init(int cpu)
{
	cpu_data_t		*cdp = cpu_data_ptr[cpu];
	cpu_desc_index_t	*cdi;
        vm_offset_t 		user_window;
        vm_offset_t 		phys_window;
        vm_offset_t 		vaddr;
	int			num_cpus;

	num_cpus = ml_get_max_cpus();

	if (cpu >= num_cpus)
	        panic("copy_window_init: cpu > num_cpus");

	if (user_window_base == 0) {

	        if (vm_allocate(kernel_map, &vaddr,
				(NBPDE * NCOPY_WINDOWS * num_cpus) + NBPDE,
				VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
		        panic("copy_window_init: "
				"couldn't allocate user map window");

		/*
		 * window must start on a page table boundary
		 * in the virtual address space
		 */
		user_window_base = (vaddr + (NBPDE - 1)) & ~(NBPDE - 1);

		/*
		 * get rid of any allocation leading up to our
		 * starting boundary
		 */
		vm_deallocate(kernel_map, vaddr, user_window_base - vaddr);

		/*
		 * get rid of tail that we don't need
		 */
		user_window = user_window_base +
					(NBPDE * NCOPY_WINDOWS * num_cpus);

		vm_deallocate(kernel_map, user_window,
				(vaddr +
				 ((NBPDE * NCOPY_WINDOWS * num_cpus) + NBPDE)) -
				 user_window);

	        if (vm_allocate(kernel_map, &phys_window_base,
				PAGE_SIZE * num_cpus, VM_FLAGS_ANYWHERE)
					!= KERN_SUCCESS)
		        panic("copy_window_init: "
				"couldn't allocate phys map window");
	}

	user_window = user_window_base + (cpu * NCOPY_WINDOWS * NBPDE);
	phys_window = phys_window_base + (cpu * PAGE_SIZE);

	cdi = &cdp->cpu_desc_index;
	  
	cdp->cpu_copywindow_base = user_window;
	cdp->cpu_copywindow_pdp  = pmap_pde(kernel_pmap, user_window);

	cdi->cdi_gdt[sel_idx(USER_WINDOW_SEL)] = userwindow_desc_pattern;
	cdi->cdi_gdt[sel_idx(USER_WINDOW_SEL)].offset = user_window;

	fix_desc(&cdi->cdi_gdt[sel_idx(USER_WINDOW_SEL)], 1);

	cdp->cpu_physwindow_base = phys_window;

	/*
	 * make sure the page that encompasses the
	 * pte pointer we're interested in actually
	 * exists in the page table
	 */
	pmap_expand(kernel_pmap, phys_window);

	cdp->cpu_physwindow_ptep = vtopte(phys_window);

	cdi->cdi_gdt[sel_idx(PHYS_WINDOW_SEL)] = physwindow_desc_pattern;
	cdi->cdi_gdt[sel_idx(PHYS_WINDOW_SEL)].offset = phys_window;

	fix_desc(&cdi->cdi_gdt[sel_idx(PHYS_WINDOW_SEL)], 1);
}


typedef struct {
	uint16_t	length;
	uint32_t	offset[2];
} __attribute__((__packed__)) table_descriptor64_t;

extern	table_descriptor64_t	gdtptr64;
extern	table_descriptor64_t	idtptr64;
/*
 * Load the segment descriptor tables for the current processor.
 */
void
cpu_desc_load64(cpu_data_t *cdp)
{
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

 	/*
	 * Load up the new descriptors etc
	 * ml_load_desc64() expects these global pseudo-descriptors:
	 *   gdtptr64 -> master_gdt
	 *   idtptr64 -> master_idt64
	 * These are 10-byte descriptors with 64-bit addresses into
	 * uber-space.
	 */
	gdtptr64.length = sizeof(master_gdt) - 1;
	gdtptr64.offset[0] = (uint32_t) cdi->cdi_gdt;
	gdtptr64.offset[1] = KERNEL_UBER_BASE_HI32;
	idtptr64.length = sizeof(master_idt64) - 1;
	idtptr64.offset[0] = (uint32_t) cdi->cdi_idt;
	idtptr64.offset[1] = KERNEL_UBER_BASE_HI32;

	/* Make sure busy bit is cleared in the TSS */
	gdt_desc_p(KERNEL_TSS)->access &= ~ACC_TSS_BUSY;
	
	ml_load_desc64();

	kprintf("64-bit descriptor tables loaded\n");
}
