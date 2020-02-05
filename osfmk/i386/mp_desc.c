/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
#include <mach/machine/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <i386/bit_routines.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/pmap.h>
#include <i386/postcode.h>
#include <i386/pmap_internal.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif

#include <kern/misc_protos.h>

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */
#include <san/kasan.h>

#define K_INTR_GATE (ACC_P|ACC_PL_K|ACC_INTR_GATE)
#define U_INTR_GATE (ACC_P|ACC_PL_U|ACC_INTR_GATE)

// Declare macros that will declare the externs
#define TRAP(n, name)           extern void *name ;
#define TRAP_ERR(n, name)       extern void *name ;
#define TRAP_SPC(n, name)       extern void *name ;
#define TRAP_IST1(n, name)      extern void *name ;
#define TRAP_IST2(n, name)      extern void *name ;
#define INTERRUPT(n)            extern void *_intr_ ## n ;
#define USER_TRAP(n, name)      extern void *name ;
#define USER_TRAP_SPC(n, name)  extern void *name ;

// Include the table to declare the externs
#include "../x86_64/idt_table.h"

// Undef the macros, then redefine them so we can declare the table
#undef TRAP
#undef TRAP_ERR
#undef TRAP_SPC
#undef TRAP_IST1
#undef TRAP_IST2
#undef INTERRUPT
#undef USER_TRAP
#undef USER_TRAP_SPC

#define TRAP(n, name)                   \
	[n] = {                         \
	        (uintptr_t)&name,       \
	        KERNEL64_CS,            \
	        0,                      \
	        K_INTR_GATE,            \
	        0                       \
	},

#define TRAP_ERR TRAP
#define TRAP_SPC TRAP

#define TRAP_IST1(n, name) \
	[n] = {                         \
	        (uintptr_t)&name,       \
	        KERNEL64_CS,            \
	        1,                      \
	        K_INTR_GATE,            \
	        0                       \
	},

#define TRAP_IST2(n, name) \
	[n] = {                         \
	        (uintptr_t)&name,       \
	        KERNEL64_CS,            \
	        2,                      \
	        K_INTR_GATE,            \
	        0                       \
	},

#define INTERRUPT(n) \
	[n] = {                         \
	        (uintptr_t)&_intr_ ## n,\
	        KERNEL64_CS,            \
	        0,                      \
	        K_INTR_GATE,            \
	        0                       \
	},

#define USER_TRAP(n, name) \
	[n] = {                         \
	        (uintptr_t)&name,       \
	        KERNEL64_CS,            \
	        0,                      \
	        U_INTR_GATE,            \
	        0                       \
	},

#define USER_TRAP_SPC USER_TRAP

// Declare the table using the macros we just set up
struct fake_descriptor64 master_idt64[IDTSZ]
__attribute__ ((section("__HIB,__desc")))
__attribute__ ((aligned(PAGE_SIZE))) = {
#include "../x86_64/idt_table.h"
};

/*
 * First cpu`s interrupt stack.
 */
extern uint32_t         low_intstack[];         /* bottom */
extern uint32_t         low_eintstack[];        /* top */

/*
 * Per-cpu data area pointers.
 */
cpu_data_t cpshadows[MAX_CPUS] __attribute__((aligned(64))) __attribute__((section("__HIB, __desc")));
cpu_data_t scdatas[MAX_CPUS] __attribute__((aligned(64))) = {
	[0].cpu_this = &scdatas[0],
	[0].cpu_nanotime = &pal_rtc_nanotime_info,
	[0].cpu_int_stack_top = (vm_offset_t) low_eintstack,
	[0].cd_shadow = &cpshadows[0]
};
cpu_data_t *cpu_data_master = &scdatas[0];

cpu_data_t      *cpu_data_ptr[MAX_CPUS] = {[0] = &scdatas[0] };

decl_simple_lock_data(, ncpus_lock);     /* protects real_ncpus */
unsigned int    real_ncpus = 1;
unsigned int    max_ncpus = MAX_CPUS;

extern void hi64_sysenter(void);
extern void hi64_syscall(void);

typedef struct {
	struct real_descriptor pcldts[LDTSZ];
} cldt_t;

cpu_desc_table64_t scdtables[MAX_CPUS] __attribute__((aligned(64))) __attribute__((section("__HIB, __desc")));
cpu_fault_stack_t scfstks[MAX_CPUS] __attribute__((aligned(64))) __attribute__((section("__HIB, __desc")));

cldt_t *dyn_ldts;

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

/*
 * This is the expanded, 64-bit variant of the kernel LDT descriptor.
 * When switching to 64-bit mode this replaces KERNEL_LDT entry
 * and the following empty slot. This enables the LDT to be referenced
 * in the uber-space remapping window on the kernel.
 */
struct fake_descriptor64 kernel_ldt_desc64 = {
	.offset64 = 0,
	.lim_or_seg = LDTSZ_MIN * sizeof(struct fake_descriptor) - 1,
	.size_or_IST = 0,
	.access = ACC_P | ACC_PL_K | ACC_LDT,
	.reserved = 0
};

/*
 * This is the expanded, 64-bit variant of the kernel TSS descriptor.
 * It is follows pattern of the KERNEL_LDT.
 */
struct fake_descriptor64 kernel_tss_desc64 = {
	.offset64 = 0,
	.lim_or_seg = sizeof(struct x86_64_tss) - 1,
	.size_or_IST = 0,
	.access = ACC_P | ACC_PL_K | ACC_TSS,
	.reserved = 0
};

/*
 * Convert a descriptor from fake to real format.
 *
 * Fake descriptor format:
 *	bytes 0..3		base 31..0
 *	bytes 4..5		limit 15..0
 *	byte  6			access byte 2 | limit 19..16
 *	byte  7			access byte 1
 *
 * Real descriptor format:
 *	bytes 0..1		limit 15..0
 *	bytes 2..3		base 15..0
 *	byte  4			base 23..16
 *	byte  5			access byte 1
 *	byte  6			access byte 2 | limit 19..16
 *	byte  7			base 31..24
 *
 * Fake gate format:
 *	bytes 0..3		offset
 *	bytes 4..5		selector
 *	byte  6			word count << 4 (to match fake descriptor)
 *	byte  7			access byte 1
 *
 * Real gate format:
 *	bytes 0..1		offset 15..0
 *	bytes 2..3		selector
 *	byte  4			word count
 *	byte  5			access byte 1
 *	bytes 6..7		offset 31..16
 */
void
fix_desc(void *d, int num_desc)
{
	uint8_t *desc = (uint8_t*) d;

	do {
		if ((desc[7] & 0x14) == 0x04) { /* gate */
			uint32_t offset;
			uint16_t selector;
			uint8_t wordcount;
			uint8_t acc;

			offset = *((uint32_t*)(desc));
			selector = *((uint32_t*)(desc + 4));
			wordcount = desc[6] >> 4;
			acc = desc[7];

			*((uint16_t*)desc) = offset & 0xFFFF;
			*((uint16_t*)(desc + 2)) = selector;
			desc[4] = wordcount;
			desc[5] = acc;
			*((uint16_t*)(desc + 6)) = offset >> 16;
		} else { /* descriptor */
			uint32_t base;
			uint16_t limit;
			uint8_t acc1, acc2;

			base = *((uint32_t*)(desc));
			limit = *((uint16_t*)(desc + 4));
			acc2 = desc[6];
			acc1 = desc[7];

			*((uint16_t*)(desc)) = limit;
			*((uint16_t*)(desc + 2)) = base & 0xFFFF;
			desc[4] = (base >> 16) & 0xFF;
			desc[5] = acc1;
			desc[6] = acc2;
			desc[7] = base >> 24;
		}
		desc += 8;
	} while (--num_desc);
}

void
fix_desc64(void *descp, int count)
{
	struct fake_descriptor64        *fakep;
	union {
		struct real_gate64              gate;
		struct real_descriptor64        desc;
	}                               real;
	int                             i;

	fakep = (struct fake_descriptor64 *) descp;

	for (i = 0; i < count; i++, fakep++) {
		/*
		 * Construct the real decriptor locally.
		 */

		bzero((void *) &real, sizeof(real));

		switch (fakep->access & ACC_TYPE) {
		case 0:
			break;
		case ACC_CALL_GATE:
		case ACC_INTR_GATE:
		case ACC_TRAP_GATE:
			real.gate.offset_low16 = (uint16_t)(fakep->offset64 & 0xFFFF);
			real.gate.selector16 = fakep->lim_or_seg & 0xFFFF;
			real.gate.IST = fakep->size_or_IST & 0x7;
			real.gate.access8 = fakep->access;
			real.gate.offset_high16 = (uint16_t)((fakep->offset64 >> 16) & 0xFFFF);
			real.gate.offset_top32 = (uint32_t)(fakep->offset64 >> 32);
			break;
		default:        /* Otherwise */
			real.desc.limit_low16 = fakep->lim_or_seg & 0xFFFF;
			real.desc.base_low16 = (uint16_t)(fakep->offset64 & 0xFFFF);
			real.desc.base_med8 = (uint8_t)((fakep->offset64 >> 16) & 0xFF);
			real.desc.access8 = fakep->access;
			real.desc.limit_high4 = (fakep->lim_or_seg >> 16) & 0xFF;
			real.desc.granularity4 = fakep->size_or_IST;
			real.desc.base_high8 = (uint8_t)((fakep->offset64 >> 24) & 0xFF);
			real.desc.base_top32 = (uint32_t)(fakep->offset64 >> 32);
		}

		/*
		 * Now copy back over the fake structure.
		 */
		bcopy((void *) &real, (void *) fakep, sizeof(real));
	}
}

extern unsigned mldtsz;
void
cpu_desc_init(cpu_data_t *cdp)
{
	cpu_desc_index_t        *cdi = &cdp->cpu_desc_index;

	if (cdp == cpu_data_master) {
		/*
		 * Populate the double-mapped 'u' and base 'b' fields in the
		 * KTSS with I/G/LDT and sysenter stack data.
		 */
		cdi->cdi_ktssu = (void *)DBLMAP(&master_ktss64);
		cdi->cdi_ktssb = (void *)&master_ktss64;
		cdi->cdi_sstku = (vm_offset_t) DBLMAP(&master_sstk.top);
		cdi->cdi_sstkb = (vm_offset_t) &master_sstk.top;

		cdi->cdi_gdtu.ptr = (void *)DBLMAP((uintptr_t) &master_gdt);
		cdi->cdi_gdtb.ptr = (void *)&master_gdt;
		cdi->cdi_idtu.ptr  = (void *)DBLMAP((uintptr_t) &master_idt64);
		cdi->cdi_idtb.ptr  = (void *)((uintptr_t) &master_idt64);
		cdi->cdi_ldtu  = (struct real_descriptor *)DBLMAP((uintptr_t)&master_ldt[0]);
		cdi->cdi_ldtb  = &master_ldt[0];

		/* Replace the expanded LDTs and TSS slots in the GDT */
		kernel_ldt_desc64.offset64 = (uintptr_t) cdi->cdi_ldtu;
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_LDT)] =
		    kernel_ldt_desc64;
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(USER_LDT)] =
		    kernel_ldt_desc64;
		kernel_tss_desc64.offset64 = (uintptr_t) DBLMAP(&master_ktss64);
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_TSS)] =
		    kernel_tss_desc64;

		/* Fix up the expanded descriptors for 64-bit. */
		fix_desc64((void *) &master_idt64, IDTSZ);
		fix_desc64((void *) &master_gdt[sel_idx(KERNEL_LDT)], 1);
		fix_desc64((void *) &master_gdt[sel_idx(USER_LDT)], 1);
		fix_desc64((void *) &master_gdt[sel_idx(KERNEL_TSS)], 1);

		/*
		 * Set the NMI/fault stacks as IST2/IST1 in the 64-bit TSS
		 */
		master_ktss64.ist2 = (uintptr_t) low_eintstack;
		master_ktss64.ist1 = (uintptr_t) low_eintstack - sizeof(x86_64_intr_stack_frame_t);
	} else if (cdi->cdi_ktssu == NULL) {    /* Skipping re-init on wake */
		cpu_desc_table64_t      *cdt = (cpu_desc_table64_t *) cdp->cpu_desc_tablep;

		cdi->cdi_idtu.ptr  = (void *)DBLMAP((uintptr_t) &master_idt64);

		cdi->cdi_ktssu = (void *)DBLMAP(&cdt->ktss);
		cdi->cdi_ktssb = (void *)(&cdt->ktss);
		cdi->cdi_sstku = (vm_offset_t)DBLMAP(&cdt->sstk.top);
		cdi->cdi_sstkb = (vm_offset_t)(&cdt->sstk.top);
		cdi->cdi_ldtu  = (void *)LDTALIAS(cdp->cpu_ldtp);
		cdi->cdi_ldtb  = (void *)(cdp->cpu_ldtp);

		/*
		 * Copy the tables
		 */
		bcopy((char *)master_gdt, (char *)cdt->gdt, sizeof(master_gdt));
		bcopy((char *)master_ldt, (char *)cdp->cpu_ldtp, mldtsz);
		bcopy((char *)&master_ktss64, (char *)&cdt->ktss, sizeof(struct x86_64_tss));
		cdi->cdi_gdtu.ptr  = (void *)DBLMAP(cdt->gdt);
		cdi->cdi_gdtb.ptr  = (void *)(cdt->gdt);
		/*
		 * Fix up the entries in the GDT to point to
		 * this LDT and this TSS.
		 * Note reuse of global 'kernel_ldt_desc64, which is not
		 * concurrency-safe. Higher level synchronization is expected
		 */
		kernel_ldt_desc64.offset64 = (uintptr_t) cdi->cdi_ldtu;
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_LDT)] =
		    kernel_ldt_desc64;
		fix_desc64(&cdt->gdt[sel_idx(KERNEL_LDT)], 1);

		kernel_ldt_desc64.offset64 = (uintptr_t) cdi->cdi_ldtu;
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(USER_LDT)] =
		    kernel_ldt_desc64;
		fix_desc64(&cdt->gdt[sel_idx(USER_LDT)], 1);

		kernel_tss_desc64.offset64 = (uintptr_t) cdi->cdi_ktssu;
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_TSS)] =
		    kernel_tss_desc64;
		fix_desc64(&cdt->gdt[sel_idx(KERNEL_TSS)], 1);

		/* Set (zeroed) fault stack as IST1, NMI intr stack IST2 */
		uint8_t *cfstk = &scfstks[cdp->cpu_number].fstk[0];
		cdt->fstkp = cfstk;
		bzero((void *) cfstk, FSTK_SZ);
		cdt->ktss.ist2 = DBLMAP((uint64_t)cdt->fstkp + FSTK_SZ);
		cdt->ktss.ist1 = cdt->ktss.ist2 - sizeof(x86_64_intr_stack_frame_t);
	}

	/* Require that the top of the sysenter stack is 16-byte aligned */
	if ((cdi->cdi_sstku % 16) != 0) {
		panic("cpu_desc_init() sysenter stack not 16-byte aligned");
	}
}
void
cpu_desc_load(cpu_data_t *cdp)
{
	cpu_desc_index_t        *cdi = &cdp->cpu_desc_index;

	postcode(CPU_DESC_LOAD_ENTRY);

	/* Stuff the kernel per-cpu data area address into the MSRs */
	postcode(CPU_DESC_LOAD_GS_BASE);
	wrmsr64(MSR_IA32_GS_BASE, (uintptr_t) cdp);
	postcode(CPU_DESC_LOAD_KERNEL_GS_BASE);
	wrmsr64(MSR_IA32_KERNEL_GS_BASE, (uintptr_t) cdp);

	/*
	 * Ensure the TSS segment's busy bit is clear. This is required
	 * for the case of reloading descriptors at wake to avoid
	 * their complete re-initialization.
	 */
	gdt_desc_p(KERNEL_TSS)->access &= ~ACC_TSS_BUSY;

	/* Load the GDT, LDT, IDT and TSS */
	cdi->cdi_gdtb.size = sizeof(struct real_descriptor) * GDTSZ - 1;
	cdi->cdi_gdtu.size = cdi->cdi_gdtb.size;
	cdi->cdi_idtb.size = 0x1000 + cdp->cpu_number;
	cdi->cdi_idtu.size = cdi->cdi_idtb.size;

	postcode(CPU_DESC_LOAD_GDT);
	lgdt((uintptr_t *) &cdi->cdi_gdtu);
	postcode(CPU_DESC_LOAD_IDT);
	lidt((uintptr_t *) &cdi->cdi_idtu);
	postcode(CPU_DESC_LOAD_LDT);
	lldt(KERNEL_LDT);
	postcode(CPU_DESC_LOAD_TSS);
	set_tr(KERNEL_TSS);

	postcode(CPU_DESC_LOAD_EXIT);
}

/*
 * Set MSRs for sysenter/sysexit and syscall/sysret for 64-bit.
 */
void
cpu_syscall_init(cpu_data_t *cdp)
{
#pragma unused(cdp)

	wrmsr64(MSR_IA32_SYSENTER_CS, SYSENTER_CS);
	wrmsr64(MSR_IA32_SYSENTER_EIP, DBLMAP((uintptr_t) hi64_sysenter));
	wrmsr64(MSR_IA32_SYSENTER_ESP, current_cpu_datap()->cpu_desc_index.cdi_sstku);
	/* Enable syscall/sysret */
	wrmsr64(MSR_IA32_EFER, rdmsr64(MSR_IA32_EFER) | MSR_IA32_EFER_SCE);

	/*
	 * MSRs for 64-bit syscall/sysret
	 * Note USER_CS because sysret uses this + 16 when returning to
	 * 64-bit code.
	 */
	wrmsr64(MSR_IA32_LSTAR, DBLMAP((uintptr_t) hi64_syscall));
	wrmsr64(MSR_IA32_STAR, (((uint64_t)USER_CS) << 48) | (((uint64_t)KERNEL64_CS) << 32));
	/*
	 * Emulate eflags cleared by sysenter but note that
	 * we also clear the trace trap to avoid the complications
	 * of single-stepping into a syscall. The nested task bit
	 * is also cleared to avoid a spurious "task switch"
	 * should we choose to return via an IRET.
	 */
	wrmsr64(MSR_IA32_FMASK, EFL_DF | EFL_IF | EFL_TF | EFL_NT);
}
extern vm_offset_t dyn_dblmap(vm_offset_t, vm_offset_t);
uint64_t ldt_alias_offset;

cpu_data_t *
cpu_data_alloc(boolean_t is_boot_cpu)
{
	int             ret;
	cpu_data_t      *cdp;

	if (is_boot_cpu) {
		assert(real_ncpus == 1);
		cdp = cpu_datap(0);
		if (cdp->cpu_processor == NULL) {
			simple_lock_init(&ncpus_lock, 0);
			cdp->cpu_processor = cpu_processor_alloc(TRUE);
#if NCOPY_WINDOWS > 0
			cdp->cpu_pmap = pmap_cpu_alloc(TRUE);
#endif
		}
		return cdp;
	}

	boolean_t do_ldt_alloc = FALSE;
	simple_lock(&ncpus_lock, LCK_GRP_NULL);
	int cnum = real_ncpus;
	real_ncpus++;
	if (dyn_ldts == NULL) {
		do_ldt_alloc = TRUE;
	}
	simple_unlock(&ncpus_lock);

	/*
	 * Allocate per-cpu data:
	 */

	cdp = &scdatas[cnum];
	bzero((void*) cdp, sizeof(cpu_data_t));
	cdp->cpu_this = cdp;
	cdp->cpu_number = cnum;
	cdp->cd_shadow = &cpshadows[cnum];
	/*
	 * Allocate interrupt stack:
	 */
	ret = kmem_alloc(kernel_map,
	    (vm_offset_t *) &cdp->cpu_int_stack_top,
	    INTSTACK_SIZE, VM_KERN_MEMORY_CPU);
	if (ret != KERN_SUCCESS) {
		panic("cpu_data_alloc() int stack failed, ret=%d\n", ret);
	}
	bzero((void*) cdp->cpu_int_stack_top, INTSTACK_SIZE);
	cdp->cpu_int_stack_top += INTSTACK_SIZE;

	/*
	 * Allocate descriptor table:
	 */

	cdp->cpu_desc_tablep = (struct cpu_desc_table *) &scdtables[cnum];
	/*
	 * Allocate LDT
	 */
	if (do_ldt_alloc) {
		boolean_t do_ldt_free = FALSE;
		vm_offset_t sldtoffset = 0;
		/*
		 * Allocate LDT
		 */
		vm_offset_t ldtalloc = 0, ldtallocsz = round_page_64(MAX_CPUS * sizeof(struct real_descriptor) * LDTSZ);
		ret = kmem_alloc(kernel_map, (vm_offset_t *) &ldtalloc, ldtallocsz, VM_KERN_MEMORY_CPU);
		if (ret != KERN_SUCCESS) {
			panic("cpu_data_alloc() ldt failed, kmem_alloc=%d\n", ret);
		}

		simple_lock(&ncpus_lock, LCK_GRP_NULL);
		if (dyn_ldts == NULL) {
			dyn_ldts = (cldt_t *)ldtalloc;
		} else {
			do_ldt_free = TRUE;
		}
		simple_unlock(&ncpus_lock);

		if (do_ldt_free) {
			kmem_free(kernel_map, ldtalloc, ldtallocsz);
		} else {
			/* CPU registration and startup are expected to execute
			 * serially, as invoked by the platform driver.
			 * Create trampoline alias of LDT region.
			 */
			sldtoffset = dyn_dblmap(ldtalloc, ldtallocsz);
			ldt_alias_offset = sldtoffset;
		}
	}
	cdp->cpu_ldtp = &dyn_ldts[cnum].pcldts[0];

#if CONFIG_MCA
	/* Machine-check shadow register allocation. */
	mca_cpu_alloc(cdp);
#endif

	/*
	 * Before this cpu has been assigned a real thread context,
	 * we give it a fake, unique, non-zero thread id which the locking
	 * primitives use as their lock value.
	 * Note that this does not apply to the boot processor, cpu 0, which
	 * transitions to a thread context well before other processors are
	 * started.
	 */
	cdp->cpu_active_thread = (thread_t) (uintptr_t) cdp->cpu_number;
	cdp->cpu_NMI_acknowledged = TRUE;
	cdp->cpu_nanotime = &pal_rtc_nanotime_info;

	kprintf("cpu_data_alloc(%d) %p desc_table: %p "
	    "ldt: %p "
	    "int_stack: 0x%lx-0x%lx\n",
	    cdp->cpu_number, cdp, cdp->cpu_desc_tablep, cdp->cpu_ldtp,
	    (long)(cdp->cpu_int_stack_top - INTSTACK_SIZE), (long)(cdp->cpu_int_stack_top));
	cpu_data_ptr[cnum] = cdp;

	return cdp;
}

boolean_t
valid_user_data_selector(uint16_t selector)
{
	sel_t       sel = selector_to_sel(selector);

	if (selector == 0) {
		return TRUE;
	}

	if (sel.ti == SEL_LDT) {
		return TRUE;
	} else if (sel.index < GDTSZ) {
		if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U) {
			return TRUE;
		}
	}
	return FALSE;
}

boolean_t
valid_user_code_selector(uint16_t selector)
{
	sel_t       sel = selector_to_sel(selector);

	if (selector == 0) {
		return FALSE;
	}

	if (sel.ti == SEL_LDT) {
		if (sel.rpl == USER_PRIV) {
			return TRUE;
		}
	} else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
		if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U) {
			return TRUE;
		}
		/* Explicitly validate the system code selectors
		 * even if not instantaneously privileged,
		 * since they are dynamically re-privileged
		 * at context switch
		 */
		if ((selector == USER_CS) || (selector == USER64_CS)) {
			return TRUE;
		}
	}

	return FALSE;
}

boolean_t
valid_user_stack_selector(uint16_t selector)
{
	sel_t       sel = selector_to_sel(selector);

	if (selector == 0) {
		return FALSE;
	}

	if (sel.ti == SEL_LDT) {
		if (sel.rpl == USER_PRIV) {
			return TRUE;
		}
	} else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
		if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U) {
			return TRUE;
		}
	}

	return FALSE;
}

boolean_t
valid_user_segment_selectors(uint16_t cs,
    uint16_t ss,
    uint16_t ds,
    uint16_t es,
    uint16_t fs,
    uint16_t gs)
{
	return valid_user_code_selector(cs) &&
	       valid_user_stack_selector(ss) &&
	       valid_user_data_selector(ds) &&
	       valid_user_data_selector(es) &&
	       valid_user_data_selector(fs) &&
	       valid_user_data_selector(gs);
}

#if NCOPY_WINDOWS > 0

static vm_offset_t user_window_base = 0;

void
cpu_userwindow_init(int cpu)
{
	cpu_data_t              *cdp = cpu_data_ptr[cpu];
	vm_offset_t             user_window;
	vm_offset_t             vaddr;
	int                     num_cpus;

	num_cpus = ml_get_max_cpus();

	if (cpu >= num_cpus) {
		panic("cpu_userwindow_init: cpu > num_cpus");
	}

	if (user_window_base == 0) {
		if (vm_allocate(kernel_map, &vaddr,
		    (NBPDE * NCOPY_WINDOWS * num_cpus) + NBPDE,
		    VM_FLAGS_ANYWHERE | VM_MAKE_TAG(VM_KERN_MEMORY_CPU)) != KERN_SUCCESS) {
			panic("cpu_userwindow_init: "
			    "couldn't allocate user map window");
		}

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
	}

	user_window = user_window_base + (cpu * NCOPY_WINDOWS * NBPDE);

	cdp->cpu_copywindow_base = user_window;
	/*
	 * Abuse this pdp entry, the pdp now actually points to
	 * an array of copy windows addresses.
	 */
	cdp->cpu_copywindow_pdp  = pmap_pde(kernel_pmap, user_window);
}

void
cpu_physwindow_init(int cpu)
{
	cpu_data_t              *cdp = cpu_data_ptr[cpu];
	vm_offset_t             phys_window = cdp->cpu_physwindow_base;

	if (phys_window == 0) {
		if (vm_allocate(kernel_map, &phys_window,
		    PAGE_SIZE, VM_FLAGS_ANYWHERE | VM_MAKE_TAG(VM_KERN_MEMORY_CPU))
		    != KERN_SUCCESS) {
			panic("cpu_physwindow_init: "
			    "couldn't allocate phys map window");
		}

		/*
		 * make sure the page that encompasses the
		 * pte pointer we're interested in actually
		 * exists in the page table
		 */
		pmap_expand(kernel_pmap, phys_window, PMAP_EXPAND_OPTIONS_NONE);

		cdp->cpu_physwindow_base = phys_window;
		cdp->cpu_physwindow_ptep = vtopte(phys_window);
	}
}
#endif /* NCOPY_WINDOWS > 0 */

/*
 * Allocate a new interrupt stack for the boot processor from the
 * heap rather than continue to use the statically allocated space.
 * Also switch to a dynamically allocated cpu data area.
 */
void
cpu_data_realloc(void)
{
	int             ret;
	vm_offset_t     istk;
	cpu_data_t      *cdp;
	boolean_t       istate;

	ret = kmem_alloc(kernel_map, &istk, INTSTACK_SIZE, VM_KERN_MEMORY_CPU);
	if (ret != KERN_SUCCESS) {
		panic("cpu_data_realloc() stack alloc, ret=%d\n", ret);
	}
	bzero((void*) istk, INTSTACK_SIZE);
	istk += INTSTACK_SIZE;

	cdp = &scdatas[0];

	/* Copy old contents into new area and make fix-ups */
	assert(cpu_number() == 0);
	bcopy((void *) cpu_data_ptr[0], (void*) cdp, sizeof(cpu_data_t));
	cdp->cpu_this = cdp;
	cdp->cpu_int_stack_top = istk;
	timer_call_queue_init(&cdp->rtclock_timer.queue);
	cdp->cpu_desc_tablep = (struct cpu_desc_table *) &scdtables[0];
	cpu_desc_table64_t      *cdt = (cpu_desc_table64_t *) cdp->cpu_desc_tablep;

	uint8_t *cfstk = &scfstks[cdp->cpu_number].fstk[0];
	cdt->fstkp = cfstk;
	cfstk += FSTK_SZ;

	/*
	 * With interrupts disabled commmit the new areas.
	 */
	istate = ml_set_interrupts_enabled(FALSE);
	cpu_data_ptr[0] = cdp;
	master_ktss64.ist2 = DBLMAP((uintptr_t) cfstk);
	master_ktss64.ist1 = DBLMAP((uintptr_t) cfstk - sizeof(x86_64_intr_stack_frame_t));
	wrmsr64(MSR_IA32_GS_BASE, (uintptr_t) cdp);
	wrmsr64(MSR_IA32_KERNEL_GS_BASE, (uintptr_t) cdp);
	(void) ml_set_interrupts_enabled(istate);

	kprintf("Reallocated master cpu data: %p,"
	    " interrupt stack: %p, fault stack: %p\n",
	    (void *) cdp, (void *) istk, (void *) cfstk);
}
