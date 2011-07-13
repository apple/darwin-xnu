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

#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <kern/etimer.h>
#include <mach/vm_map.h>
#include <mach/machine/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <i386/lock.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/pmap.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif

#include <kern/misc_protos.h>

#include <mach_kdb.h>

#ifdef __x86_64__
#define K_INTR_GATE (ACC_P|ACC_PL_K|ACC_INTR_GATE)
#define U_INTR_GATE (ACC_P|ACC_PL_U|ACC_INTR_GATE)

// Declare macros that will declare the externs
#define TRAP(n, name)		extern void *name ;
#define TRAP_ERR(n, name)	extern void *name ;
#define TRAP_SPC(n, name)	extern void *name ;
#define TRAP_IST(n, name)	extern void *name ;
#define INTERRUPT(n)		extern void *_intr_ ## n ;
#define USER_TRAP(n, name)	extern void *name ;
#define USER_TRAP_SPC(n, name)	extern void *name ;

// Include the table to declare the externs
#include "../x86_64/idt_table.h"

// Undef the macros, then redefine them so we can declare the table
#undef TRAP
#undef TRAP_ERR
#undef TRAP_SPC
#undef TRAP_IST
#undef INTERRUPT
#undef USER_TRAP
#undef USER_TRAP_SPC

#define TRAP(n, name)			\
	[n] = {				\
		(uintptr_t)&name,	\
		KERNEL64_CS,		\
		0,			\
		K_INTR_GATE,		\
		0			\
	},

#define TRAP_ERR TRAP
#define TRAP_SPC TRAP

#define TRAP_IST(n, name) \
	[n] = {				\
		(uintptr_t)&name,	\
		KERNEL64_CS,		\
		1,			\
		K_INTR_GATE,		\
		0			\
	},

#define INTERRUPT(n) \
	[n] = {				\
		(uintptr_t)&_intr_ ## n,\
		KERNEL64_CS,		\
		0,			\
		K_INTR_GATE,		\
		0			\
	},

#define USER_TRAP(n, name) \
	[n] = {				\
		(uintptr_t)&name,	\
		KERNEL64_CS,		\
		0,			\
		U_INTR_GATE,		\
		0			\
	},

#define USER_TRAP_SPC USER_TRAP
			 

// Declare the table using the macros we just set up
struct fake_descriptor64 master_idt64[IDTSZ] __attribute__ ((aligned (4096))) = {
#include "../x86_64/idt_table.h"
};
#endif

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
cpu_data_t	cpu_data_master = {
	.cpu_this = &cpu_data_master,
	.cpu_nanotime = &pal_rtc_nanotime_info,
	.cpu_int_stack_top = (vm_offset_t) low_eintstack,
#ifdef __i386__
	.cpu_is64bit = FALSE,
#else
	.cpu_is64bit = TRUE
#endif
};
cpu_data_t	*cpu_data_ptr[MAX_CPUS] = { [0] = &cpu_data_master };

decl_simple_lock_data(,ncpus_lock);	/* protects real_ncpus */
unsigned int	real_ncpus = 1;
unsigned int	max_ncpus = MAX_CPUS;

#ifdef __i386__
extern void *hi_remap_text;
#define HI_TEXT(lo_text)	\
	(((uint32_t)&lo_text - (uint32_t)&hi_remap_text) + HIGH_MEM_BASE)

extern void hi_sysenter(void);

typedef struct {
	uint16_t	length;
	uint32_t	offset[2];
} __attribute__((__packed__)) table_descriptor64_t;

extern	table_descriptor64_t	gdtptr64;
extern	table_descriptor64_t	idtptr64;
#endif
extern void hi64_sysenter(void);
extern void hi64_syscall(void);

#if defined(__x86_64__) && !defined(UBER64)
#define UBER64(x) ((uintptr_t)x)
#endif

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
	0,
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
	0,
	sizeof(struct x86_64_tss)-1,
	0,
	ACC_P|ACC_PL_K|ACC_TSS,
	0
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
fix_desc(void *d, int num_desc) {
	//early_kprintf("fix_desc(%x, %x)\n", d, num_desc);
	uint8_t *desc = (uint8_t*) d;

	do {
		if ((desc[7] & 0x14) == 0x04) { /* gate */
			uint32_t offset;
			uint16_t selector;
			uint8_t wordcount;
			uint8_t acc;
			
			offset = *((uint32_t*)(desc));
			selector = *((uint32_t*)(desc+4));
			wordcount = desc[6] >> 4;
			acc = desc[7];

			*((uint16_t*)desc) = offset & 0xFFFF;
			*((uint16_t*)(desc+2)) = selector;
			desc[4] = wordcount;
			desc[5] = acc;
			*((uint16_t*)(desc+6)) = offset >> 16;

		} else { /* descriptor */
			uint32_t base;
			uint16_t limit;
			uint8_t acc1, acc2;

			base = *((uint32_t*)(desc));
			limit = *((uint16_t*)(desc+4));
			acc2 = desc[6];
			acc1 = desc[7];

			*((uint16_t*)(desc)) = limit;
			*((uint16_t*)(desc+2)) = base & 0xFFFF;
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
	struct fake_descriptor64	*fakep;
	union {
		struct real_gate64		gate;
		struct real_descriptor64	desc;
	}				real;
	int				i;

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
			real.gate.offset_high16 = (uint16_t)((fakep->offset64>>16) & 0xFFFF);
			real.gate.offset_top32 = (uint32_t)(fakep->offset64>>32);
			break;
		default:	/* Otherwise */
			real.desc.limit_low16 = fakep->lim_or_seg & 0xFFFF;
			real.desc.base_low16 = (uint16_t)(fakep->offset64 & 0xFFFF);
			real.desc.base_med8 = (uint8_t)((fakep->offset64 >> 16) & 0xFF);
			real.desc.access8 = fakep->access;
			real.desc.limit_high4 = (fakep->lim_or_seg >> 16) & 0xFF;
			real.desc.granularity4 = fakep->size_or_IST;
			real.desc.base_high8 = (uint8_t)((fakep->offset64 >> 24) & 0xFF);
			real.desc.base_top32 = (uint32_t)(fakep->offset64>>32);
		}

		/*
		 * Now copy back over the fake structure.
		 */
		bcopy((void *) &real, (void *) fakep, sizeof(real));
	}
}

#ifdef __i386__
void
cpu_desc_init(cpu_data_t *cdp)
{
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

	if (cdp == &cpu_data_master) {
		/*
		 * Fix up the entries in the GDT to point to
		 * this LDT and this TSS.
		 */
		struct fake_descriptor temp_fake_desc;
		temp_fake_desc = ldt_desc_pattern;
		temp_fake_desc.offset = (vm_offset_t) &master_ldt;
		fix_desc(&temp_fake_desc, 1);
		*(struct fake_descriptor *) &master_gdt[sel_idx(KERNEL_LDT)] =
			temp_fake_desc;
		*(struct fake_descriptor *) &master_gdt[sel_idx(USER_LDT)] =
			temp_fake_desc;

		temp_fake_desc = tss_desc_pattern;
		temp_fake_desc.offset = (vm_offset_t) &master_ktss;
		fix_desc(&temp_fake_desc, 1);
		*(struct fake_descriptor *) &master_gdt[sel_idx(KERNEL_TSS)] =
			temp_fake_desc;

#if MACH_KDB
		temp_fake_desc = tss_desc_pattern;
		temp_fake_desc.offset = (vm_offset_t) &master_dbtss;
		fix_desc(&temp_fake_desc, 1);
		*(struct fake_descriptor *) &master_gdt[sel_idx(DEBUG_TSS)] =
			temp_fake_desc;
#endif

		temp_fake_desc = cpudata_desc_pattern;
		temp_fake_desc.offset = (vm_offset_t) &cpu_data_master;
		fix_desc(&temp_fake_desc, 1);
		*(struct fake_descriptor *) &master_gdt[sel_idx(CPU_DATA_GS)] =
			temp_fake_desc;

		fix_desc((void *)&master_idt, IDTSZ);

		cdi->cdi_idt.ptr = master_idt;
		cdi->cdi_gdt.ptr = (void *)master_gdt;


		/*
		 * Master CPU uses the tables built at boot time.
		 * Just set the index pointers to the high shared-mapping space.
		 * Note that the sysenter stack uses empty space above the ktss
		 * in the HIGH_FIXED_KTSS page. In this case we don't map the
		 * the real master_sstk in low memory.
		 */
		cdi->cdi_ktss = (struct i386_tss *)
			pmap_index_to_virt(HIGH_FIXED_KTSS) ;
		cdi->cdi_sstk = (vm_offset_t) (cdi->cdi_ktss + 1) +
				(vm_offset_t) &master_sstk.top -
				(vm_offset_t) &master_sstk;
	} else {
		cpu_desc_table_t	*cdt = (cpu_desc_table_t *) cdp->cpu_desc_tablep;

		vm_offset_t	cpu_hi_desc;

		cpu_hi_desc = pmap_cpu_high_shared_remap(
					cdp->cpu_number,
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
		cdi->cdi_gdt.ptr  = (struct fake_descriptor *) (cpu_hi_desc +
					offsetof(cpu_desc_table_t, gdt[0]));
		cdi->cdi_idt.ptr  = (struct fake_descriptor *) (cpu_hi_desc +
					offsetof(cpu_desc_table_t, idt[0]));
		cdi->cdi_ktss = (struct i386_tss *) (cpu_hi_desc +
					offsetof(cpu_desc_table_t, ktss));
		cdi->cdi_sstk = cpu_hi_desc + offsetof(cpu_desc_table_t, sstk.top);

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
		bcopy((char *)master_idt, (char *)cdt->idt, sizeof(master_idt));
		bcopy((char *)master_gdt, (char *)cdt->gdt, sizeof(master_gdt));
		bcopy((char *)master_ldt, (char *)cdp->cpu_ldtp, sizeof(master_ldt));
		bzero((char *)&cdt->ktss, sizeof(struct i386_tss)); 
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
		struct fake_descriptor temp_ldt = ldt_desc_pattern;
		temp_ldt.offset = (vm_offset_t)cdi->cdi_ldt;
		fix_desc(&temp_ldt, 1);

		cdt->gdt[sel_idx(KERNEL_LDT)] = temp_ldt;
		cdt->gdt[sel_idx(USER_LDT)] = temp_ldt;

		cdt->gdt[sel_idx(KERNEL_TSS)] = tss_desc_pattern;
		cdt->gdt[sel_idx(KERNEL_TSS)].offset = (vm_offset_t) cdi->cdi_ktss;
		fix_desc(&cdt->gdt[sel_idx(KERNEL_TSS)], 1);

		cdt->gdt[sel_idx(CPU_DATA_GS)] = cpudata_desc_pattern;
		cdt->gdt[sel_idx(CPU_DATA_GS)].offset = (vm_offset_t) cdp;
		fix_desc(&cdt->gdt[sel_idx(CPU_DATA_GS)], 1);

#if	MACH_KDB /* this only works for legacy 32-bit machines */
		cdt->gdt[sel_idx(DEBUG_TSS)] = tss_desc_pattern;
		cdt->gdt[sel_idx(DEBUG_TSS)].offset = (vm_offset_t) cdi->cdi_dbtss;
		fix_desc(&cdt->gdt[sel_idx(DEBUG_TSS)], 1);

		cdt->dbtss.esp0 = (int)(db_task_stack_store +
				(INTSTACK_SIZE * (cdp->cpu_number + 1)) - sizeof (natural_t));
		cdt->dbtss.esp = cdt->dbtss.esp0;
		cdt->dbtss.eip = (int)&db_task_start;
#endif	/* MACH_KDB */

		cdt->ktss.ss0 = KERNEL_DS;
		cdt->ktss.io_bit_map_offset = 0x0FFF;	/* no IO bitmap */

		cpu_userwindow_init(cdp->cpu_number);
		cpu_physwindow_init(cdp->cpu_number);

	}
}
#endif /* __i386__ */

void
cpu_desc_init64(cpu_data_t *cdp)
{
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

	if (cdp == &cpu_data_master) {
		/*
		 * Master CPU uses the tables built at boot time.
		 * Just set the index pointers to the low memory space.
		 */
		cdi->cdi_ktss = (void *)&master_ktss64;
		cdi->cdi_sstk = (vm_offset_t) &master_sstk.top;
		cdi->cdi_gdt.ptr  = (void *)master_gdt;
		cdi->cdi_idt.ptr  = (void *)master_idt64;
		cdi->cdi_ldt  = (struct fake_descriptor *) master_ldt;


		/* Replace the expanded LDTs and TSS slots in the GDT */
		kernel_ldt_desc64.offset64 = UBER64(&master_ldt);
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_LDT)] =
			kernel_ldt_desc64;
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(USER_LDT)] =
			kernel_ldt_desc64;
		kernel_tss_desc64.offset64 = UBER64(&master_ktss64);
		*(struct fake_descriptor64 *) &master_gdt[sel_idx(KERNEL_TSS)] =
			kernel_tss_desc64;

		/* Fix up the expanded descriptors for 64-bit. */
		fix_desc64((void *) &master_idt64, IDTSZ);
		fix_desc64((void *) &master_gdt[sel_idx(KERNEL_LDT)], 1);
		fix_desc64((void *) &master_gdt[sel_idx(USER_LDT)], 1);
		fix_desc64((void *) &master_gdt[sel_idx(KERNEL_TSS)], 1);

		/*
		 * Set the double-fault stack as IST1 in the 64-bit TSS
		 */
		master_ktss64.ist1 = UBER64((uintptr_t) df_task_stack_end);

	} else {
		cpu_desc_table64_t	*cdt = (cpu_desc_table64_t *) cdp->cpu_desc_tablep;
		/*
		 * Per-cpu GDT, IDT, KTSS descriptors are allocated in kernel 
		 * heap (cpu_desc_table). 
		 * LDT descriptors are mapped into a separate area.
		 */
		cdi->cdi_gdt.ptr  = (struct fake_descriptor *)cdt->gdt;
		cdi->cdi_idt.ptr  = (void *)cdt->idt;
		cdi->cdi_ktss = (void *)&cdt->ktss;
		cdi->cdi_sstk = (vm_offset_t)&cdt->sstk.top;
		cdi->cdi_ldt  = cdp->cpu_ldtp;

		/*
		 * Copy the tables
		 */
		bcopy((char *)master_idt64, (char *)cdt->idt, sizeof(master_idt64));
		bcopy((char *)master_gdt, (char *)cdt->gdt, sizeof(master_gdt));
		bcopy((char *)master_ldt, (char *)cdp->cpu_ldtp, sizeof(master_ldt));
		bcopy((char *)&master_ktss64, (char *)&cdt->ktss, sizeof(struct x86_64_tss));

		/*
		 * Fix up the entries in the GDT to point to
		 * this LDT and this TSS.
		 */
		kernel_ldt_desc64.offset64 = UBER64(cdi->cdi_ldt);
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_LDT)] =
			kernel_ldt_desc64;
		fix_desc64(&cdt->gdt[sel_idx(KERNEL_LDT)], 1);

		kernel_ldt_desc64.offset64 = UBER64(cdi->cdi_ldt);
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(USER_LDT)] =
			kernel_ldt_desc64;
		fix_desc64(&cdt->gdt[sel_idx(USER_LDT)], 1);

		kernel_tss_desc64.offset64 = UBER64(cdi->cdi_ktss);
		*(struct fake_descriptor64 *) &cdt->gdt[sel_idx(KERNEL_TSS)] =
			kernel_tss_desc64;
		fix_desc64(&cdt->gdt[sel_idx(KERNEL_TSS)], 1);

		/* Set (zeroed) double-fault stack as IST1 */
		bzero((void *) cdt->dfstk, sizeof(cdt->dfstk));
		cdt->ktss.ist1 = UBER64((unsigned long)cdt->dfstk + sizeof(cdt->dfstk));
#ifdef __i386__
		cdt->gdt[sel_idx(CPU_DATA_GS)] = cpudata_desc_pattern;
		cdt->gdt[sel_idx(CPU_DATA_GS)].offset = (vm_offset_t) cdp;
		fix_desc(&cdt->gdt[sel_idx(CPU_DATA_GS)], 1);

		/* Allocate copyio windows */
		cpu_userwindow_init(cdp->cpu_number);
		cpu_physwindow_init(cdp->cpu_number);
#endif
	}

	/* Require that the top of the sysenter stack is 16-byte aligned */
	if ((cdi->cdi_sstk % 16) != 0)
		panic("cpu_desc_init64() sysenter stack not 16-byte aligned");
}

#ifdef __i386__
void
cpu_desc_load(cpu_data_t *cdp)
{
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

	cdi->cdi_idt.size = 0x1000 + cdp->cpu_number;
	cdi->cdi_gdt.size = sizeof(struct real_descriptor)*GDTSZ - 1;

	lgdt((unsigned long *) &cdi->cdi_gdt);
	lidt((unsigned long *) &cdi->cdi_idt);
	lldt(KERNEL_LDT);

	set_tr(KERNEL_TSS);

	__asm__ volatile("mov %0, %%gs" : : "rm" ((unsigned short)(CPU_DATA_GS)));
}
#endif /* __i386__ */

void
cpu_desc_load64(cpu_data_t *cdp)
{
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;

#ifdef __i386__
	/*
	 * Load up the new descriptors etc
	 * ml_load_desc64() expects these global pseudo-descriptors:
	 *   gdtptr64 -> per-cpu gdt
	 *   idtptr64 -> per-cpu idt
	 * These are 10-byte descriptors with 64-bit addresses into
	 * uber-space.
	 *
 	 * Refer to commpage/cpu_number.s for the IDT limit trick.
	 */
	gdtptr64.length = GDTSZ * sizeof(struct real_descriptor) - 1;
	gdtptr64.offset[0] = (uint32_t) cdi->cdi_gdt.ptr;
	gdtptr64.offset[1] = KERNEL_UBER_BASE_HI32;
	idtptr64.length = 0x1000 + cdp->cpu_number;
	idtptr64.offset[0] = (uint32_t) cdi->cdi_idt.ptr;
	idtptr64.offset[1] = KERNEL_UBER_BASE_HI32;

	/* Make sure busy bit is cleared in the TSS */
	gdt_desc_p(KERNEL_TSS)->access &= ~ACC_TSS_BUSY;

	ml_load_desc64();
#else
	/* Load the GDT, LDT, IDT and TSS */
	cdi->cdi_gdt.size = sizeof(struct real_descriptor)*GDTSZ - 1;
	cdi->cdi_idt.size = 0x1000 + cdp->cpu_number;
	lgdt((unsigned long *) &cdi->cdi_gdt);
	lidt((unsigned long *) &cdi->cdi_idt);
	lldt(KERNEL_LDT);
	set_tr(KERNEL_TSS);

	/* Stuff the pre-cpu data area into the MSR and swapgs to activate */
	wrmsr64(MSR_IA32_KERNEL_GS_BASE, (unsigned long)cdp);
#if GPROF // Hack to enable mcount to work on K64
	__asm__ volatile("mov %0, %%gs" : : "rm" ((unsigned short)(KERNEL_DS)));
#endif
	swapgs();

	cpu_mode_init(cdp);
#endif
}

#ifdef __i386__
/*
 * Set MSRs for sysenter/sysexit for 32-bit.
 */
static void
fast_syscall_init(__unused cpu_data_t *cdp)
{
	wrmsr(MSR_IA32_SYSENTER_CS, SYSENTER_CS, 0); 
	wrmsr(MSR_IA32_SYSENTER_EIP, HI_TEXT(hi_sysenter), 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, current_sstk(), 0);
}
#endif

/*
 * Set MSRs for sysenter/sysexit and syscall/sysret for 64-bit.
 */
static void
fast_syscall_init64(__unused cpu_data_t *cdp)
{
	wrmsr64(MSR_IA32_SYSENTER_CS, SYSENTER_CS); 
	wrmsr64(MSR_IA32_SYSENTER_EIP, UBER64((uintptr_t) hi64_sysenter));
	wrmsr64(MSR_IA32_SYSENTER_ESP, UBER64(current_sstk()));
	/* Enable syscall/sysret */
	wrmsr64(MSR_IA32_EFER, rdmsr64(MSR_IA32_EFER) | MSR_IA32_EFER_SCE);

	/*
	 * MSRs for 64-bit syscall/sysret
	 * Note USER_CS because sysret uses this + 16 when returning to
	 * 64-bit code.
	 */
	wrmsr64(MSR_IA32_LSTAR, UBER64((uintptr_t) hi64_syscall));
	wrmsr64(MSR_IA32_STAR, (((uint64_t)USER_CS) << 48) |
				(((uint64_t)KERNEL64_CS) << 32));
	/*
	 * Emulate eflags cleared by sysenter but note that
	 * we also clear the trace trap to avoid the complications
	 * of single-stepping into a syscall. The nested task bit
	 * is also cleared to avoid a spurious "task switch"
	 * should we choose to return via an IRET.
	 */
	wrmsr64(MSR_IA32_FMASK, EFL_DF|EFL_IF|EFL_TF|EFL_NT);

#ifdef __i386__
	/*
	 * Set the Kernel GS base MSR to point to per-cpu data in uber-space.
	 * The uber-space handler (hi64_syscall) uses the swapgs instruction.
	 */
	wrmsr64(MSR_IA32_KERNEL_GS_BASE, UBER64(cdp));

#if ONLY_SAFE_FOR_LINDA_SERIAL
	kprintf("fast_syscall_init64() KERNEL_GS_BASE=0x%016llx\n",
			rdmsr64(MSR_IA32_KERNEL_GS_BASE));
#endif
#endif
}


cpu_data_t *
cpu_data_alloc(boolean_t is_boot_cpu)
{
	int		ret;
	cpu_data_t	*cdp;

	if (is_boot_cpu) {
		assert(real_ncpus == 1);
		cdp = &cpu_data_master;
		if (cdp->cpu_processor == NULL) {
			simple_lock_init(&ncpus_lock, 0);
			cdp->cpu_processor = cpu_processor_alloc(TRUE);
#if NCOPY_WINDOWS > 0
			cdp->cpu_pmap = pmap_cpu_alloc(TRUE);
#endif
		}
		return cdp;
	}

	/*
	 * Allocate per-cpu data:
	 */
	ret = kmem_alloc(kernel_map, (vm_offset_t *) &cdp, sizeof(cpu_data_t));
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

#if CONFIG_MCA
	/* Machine-check shadow register allocation. */
	mca_cpu_alloc(cdp);
#endif

	simple_lock(&ncpus_lock);

	cpu_data_ptr[real_ncpus] = cdp;
	cdp->cpu_number = real_ncpus;
	real_ncpus++;
	simple_unlock(&ncpus_lock);

	cdp->cpu_nanotime = &pal_rtc_nanotime_info;

	kprintf("cpu_data_alloc(%d) %p desc_table: %p "
		"ldt: %p "
		"int_stack: 0x%lx-0x%lx\n",
		cdp->cpu_number, cdp, cdp->cpu_desc_tablep, cdp->cpu_ldtp,
		(long)(cdp->cpu_int_stack_top - INTSTACK_SIZE), (long)(cdp->cpu_int_stack_top));

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
valid_user_data_selector(uint16_t selector)
{
    sel_t	sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (TRUE);

    if (sel.ti == SEL_LDT)
	return (TRUE);
    else if (sel.index < GDTSZ) {
	if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U)
	    return (TRUE);
    }
		
    return (FALSE);
}

boolean_t
valid_user_code_selector(uint16_t selector)
{
    sel_t	sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (FALSE);

    if (sel.ti == SEL_LDT) {
	if (sel.rpl == USER_PRIV)
	    return (TRUE);
    }
    else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
	if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U)
	    return (TRUE);
    }

    return (FALSE);
}

boolean_t
valid_user_stack_selector(uint16_t selector)
{
    sel_t	sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (FALSE);

    if (sel.ti == SEL_LDT) {
	if (sel.rpl == USER_PRIV)
	    return (TRUE);
    }
    else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
	if ((gdt_desc_p(selector)->access & ACC_PL_U) == ACC_PL_U)
	    return (TRUE);
    }
		
    return (FALSE);
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

#if NCOPY_WINDOWS > 0

static vm_offset_t user_window_base = 0;

void
cpu_userwindow_init(int cpu)
{
	cpu_data_t		*cdp = cpu_data_ptr[cpu];
	vm_offset_t 		user_window;
	vm_offset_t 		vaddr;
	int			num_cpus;

	num_cpus = ml_get_max_cpus();

	if (cpu >= num_cpus)
		panic("cpu_userwindow_init: cpu > num_cpus");

	if (user_window_base == 0) {

		if (vm_allocate(kernel_map, &vaddr,
					(NBPDE * NCOPY_WINDOWS * num_cpus) + NBPDE,
					VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
			panic("cpu_userwindow_init: "
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
	}

 	user_window = user_window_base + (cpu * NCOPY_WINDOWS * NBPDE);

	cdp->cpu_copywindow_base = user_window;
	/*
	 * Abuse this pdp entry, the pdp now actually points to 
	 * an array of copy windows addresses.
	 */
	cdp->cpu_copywindow_pdp  = pmap_pde(kernel_pmap, user_window);

#ifdef __i386__
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;
	cdi->cdi_gdt.ptr[sel_idx(USER_WINDOW_SEL)] = userwindow_desc_pattern;
	cdi->cdi_gdt.ptr[sel_idx(USER_WINDOW_SEL)].offset = user_window;

	fix_desc(&cdi->cdi_gdt.ptr[sel_idx(USER_WINDOW_SEL)], 1);
#endif /* __i386__ */
}

void
cpu_physwindow_init(int cpu)
{
	cpu_data_t		*cdp = cpu_data_ptr[cpu];
        vm_offset_t 		phys_window = cdp->cpu_physwindow_base;

	if (phys_window == 0) {
		if (vm_allocate(kernel_map, &phys_window,
				PAGE_SIZE, VM_FLAGS_ANYWHERE)
				!= KERN_SUCCESS)
		        panic("cpu_physwindow_init: "
				"couldn't allocate phys map window");

		/*
		 * make sure the page that encompasses the
		 * pte pointer we're interested in actually
		 * exists in the page table
		 */
		pmap_expand(kernel_pmap, phys_window);

		cdp->cpu_physwindow_base = phys_window;
		cdp->cpu_physwindow_ptep = vtopte(phys_window);
	}
#ifdef __i386__
	cpu_desc_index_t	*cdi = &cdp->cpu_desc_index;
	cdi->cdi_gdt.ptr[sel_idx(PHYS_WINDOW_SEL)] = physwindow_desc_pattern;
	cdi->cdi_gdt.ptr[sel_idx(PHYS_WINDOW_SEL)].offset = phys_window;

	fix_desc(&cdi->cdi_gdt.ptr[sel_idx(PHYS_WINDOW_SEL)], 1);
#endif /* __i386__ */
}
#endif /* NCOPY_WINDOWS > 0 */

/*
 * Load the segment descriptor tables for the current processor.
 */
void
cpu_mode_init(cpu_data_t *cdp)
{
#ifdef __i386__
	if (cdp->cpu_is64bit) {
		cpu_IA32e_enable(cdp);
		cpu_desc_load64(cdp);
		fast_syscall_init64(cdp);
	} else {
		fast_syscall_init(cdp);
	}
#else
	fast_syscall_init64(cdp);
#endif

	/* Call for per-cpu pmap mode initialization */
	pmap_cpu_init();
}

