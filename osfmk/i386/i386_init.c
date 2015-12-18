/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989, 1988 Carnegie Mellon University
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


#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/pms.h>
#include <kern/xpr.h>
#include <kern/cpu_data.h>
#include <kern/processor.h>
#include <sys/kdebug.h>
#include <console/serial_protos.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <machine/pal_routines.h>
#include <i386/fpu.h>
#include <i386/pmap.h>
#include <i386/misc_protos.h>
#include <i386/cpu_threads.h>
#include <i386/cpuid.h>
#include <i386/lapic.h>
#include <i386/mp.h>
#include <i386/mp_desc.h>
#if CONFIG_MTRR
#include <i386/mtrr.h>
#endif
#include <i386/machine_routines.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif
#include <i386/ucode.h>
#include <i386/postcode.h>
#include <i386/Diagnostics.h>
#include <i386/pmCPU.h>
#include <i386/tsc.h>
#include <i386/locks.h> /* LcksOpts */
#if DEBUG
#include <machine/pal_routines.h>
#endif
#if DEBUG
#define DBG(x...)       kprintf(x)
#else
#define DBG(x...)
#endif

int			debug_task;

static boot_args	*kernelBootArgs;

extern int		disableConsoleOutput;
extern const char	version[];
extern const char	version_variant[];
extern int		nx_enabled;

uint64_t		physmap_base, physmap_max;

pd_entry_t		*KPTphys;
pd_entry_t		*IdlePTD;
pdpt_entry_t		*IdlePDPT;
pml4_entry_t		*IdlePML4;

char *physfree;

/*
 * Note: ALLOCPAGES() can only be used safely within Idle_PTs_init()
 * due to the mutation of physfree.
 */
static void *
ALLOCPAGES(int npages)
{
	uintptr_t tmp = (uintptr_t)physfree;
	bzero(physfree, npages * PAGE_SIZE);
	physfree += npages * PAGE_SIZE;
	tmp += VM_MIN_KERNEL_ADDRESS & ~LOW_4GB_MASK;
	return (void *)tmp;
}

static void
fillkpt(pt_entry_t *base, int prot, uintptr_t src, int index, int count)
{
	int i;
	for (i=0; i<count; i++) {
		base[index] = src | prot | INTEL_PTE_VALID;
		src += PAGE_SIZE;
		index++;
	}
}

extern pmap_paddr_t first_avail;

int break_kprintf = 0;

uint64_t
x86_64_pre_sleep(void)
{
	IdlePML4[0] = IdlePML4[KERNEL_PML4_INDEX];
	uint64_t oldcr3 = get_cr3_raw();
	set_cr3_raw((uint32_t) (uintptr_t)ID_MAP_VTOP(IdlePML4));
	return oldcr3;
}

void
x86_64_post_sleep(uint64_t new_cr3)
{
	IdlePML4[0] = 0;
	set_cr3_raw((uint32_t) new_cr3);
}




// Set up the physical mapping - NPHYSMAP GB of memory mapped at a high address
// NPHYSMAP is determined by the maximum supported RAM size plus 4GB to account
// the PCI hole (which is less 4GB but not more).

/* Compile-time guard: NPHYSMAP is capped to 256GiB, accounting for
 * randomisation
 */
extern int maxphymapsupported[NPHYSMAP <= (PTE_PER_PAGE/2) ? 1 : -1];

static void
physmap_init(void)
{
	pt_entry_t *physmapL3 = ALLOCPAGES(1);
	struct {
		pt_entry_t entries[PTE_PER_PAGE];
	} * physmapL2 = ALLOCPAGES(NPHYSMAP);

	uint64_t i;
	uint8_t phys_random_L3 = early_random() & 0xFF;

	/* We assume NX support. Mark all levels of the PHYSMAP NX
	 * to avoid granting executability via a single bit flip.
	 */
#if DEVELOPMENT || DEBUG
	uint32_t reg[4];
	do_cpuid(0x80000000, reg);
	if (reg[eax] >= 0x80000001) {
		do_cpuid(0x80000001, reg);
		assert(reg[edx] & CPUID_EXTFEATURE_XD);
	}
#endif /* DEVELOPMENT || DEBUG */

	for(i = 0; i < NPHYSMAP; i++) {
		physmapL3[i + phys_random_L3] =
				((uintptr_t)ID_MAP_VTOP(&physmapL2[i]))
				| INTEL_PTE_VALID
				| INTEL_PTE_NX
				| INTEL_PTE_WRITE;

		uint64_t j;
		for(j = 0; j < PTE_PER_PAGE; j++) {
			physmapL2[i].entries[j] =
			    ((i * PTE_PER_PAGE + j) << PDSHIFT)
							| INTEL_PTE_PS
							| INTEL_PTE_VALID
							| INTEL_PTE_NX
							| INTEL_PTE_WRITE;
		}
	}

	IdlePML4[KERNEL_PHYSMAP_PML4_INDEX] =
					((uintptr_t)ID_MAP_VTOP(physmapL3))
					| INTEL_PTE_VALID
					| INTEL_PTE_NX
					| INTEL_PTE_WRITE;

	physmap_base = KVADDR(KERNEL_PHYSMAP_PML4_INDEX, phys_random_L3, 0, 0);
	physmap_max = physmap_base + NPHYSMAP * GB;
	DBG("Physical address map base: 0x%qx\n", physmap_base);
	DBG("Physical map idlepml4[%d]: 0x%llx\n",
		KERNEL_PHYSMAP_PML4_INDEX, IdlePML4[KERNEL_PHYSMAP_PML4_INDEX]);
}

static void
descriptor_alias_init()
{
	vm_offset_t	master_gdt_phys;
	vm_offset_t	master_gdt_alias_phys;
	vm_offset_t	master_idt_phys;
	vm_offset_t	master_idt_alias_phys;

	assert(((vm_offset_t)master_gdt & PAGE_MASK) == 0);
	assert(((vm_offset_t)master_idt64 & PAGE_MASK) == 0);

	master_gdt_phys       = (vm_offset_t) ID_MAP_VTOP(master_gdt);
	master_idt_phys       = (vm_offset_t) ID_MAP_VTOP(master_idt64);
	master_gdt_alias_phys = (vm_offset_t) ID_MAP_VTOP(MASTER_GDT_ALIAS);
	master_idt_alias_phys = (vm_offset_t) ID_MAP_VTOP(MASTER_IDT_ALIAS);
	
	DBG("master_gdt_phys:       %p\n", (void *) master_gdt_phys);
	DBG("master_idt_phys:       %p\n", (void *) master_idt_phys);
	DBG("master_gdt_alias_phys: %p\n", (void *) master_gdt_alias_phys);
	DBG("master_idt_alias_phys: %p\n", (void *) master_idt_alias_phys);

	KPTphys[atop_kernel(master_gdt_alias_phys)] = master_gdt_phys |
		INTEL_PTE_VALID | INTEL_PTE_NX | INTEL_PTE_WRITE;
	KPTphys[atop_kernel(master_idt_alias_phys)] = master_idt_phys |
		INTEL_PTE_VALID | INTEL_PTE_NX;	/* read-only */
}

static void
Idle_PTs_init(void)
{
	/* Allocate the "idle" kernel page tables: */
	KPTphys  = ALLOCPAGES(NKPT);		/* level 1 */
	IdlePTD  = ALLOCPAGES(NPGPTD);		/* level 2 */
	IdlePDPT = ALLOCPAGES(1);		/* level 3 */
	IdlePML4 = ALLOCPAGES(1);		/* level 4 */

	// Fill the lowest level with everything up to physfree
	fillkpt(KPTphys,
		INTEL_PTE_WRITE, 0, 0, (int)(((uintptr_t)physfree) >> PAGE_SHIFT));

	/* IdlePTD */
	fillkpt(IdlePTD,
		INTEL_PTE_WRITE, (uintptr_t)ID_MAP_VTOP(KPTphys), 0, NKPT);

	// IdlePDPT entries
	fillkpt(IdlePDPT,
		INTEL_PTE_WRITE, (uintptr_t)ID_MAP_VTOP(IdlePTD), 0, NPGPTD);

	// IdlePML4 single entry for kernel space.
	fillkpt(IdlePML4 + KERNEL_PML4_INDEX,
		INTEL_PTE_WRITE, (uintptr_t)ID_MAP_VTOP(IdlePDPT), 0, 1);
	
	postcode(VSTART_PHYSMAP_INIT);

	physmap_init();

	postcode(VSTART_DESC_ALIAS_INIT);

	descriptor_alias_init();

	postcode(VSTART_SET_CR3);

	// Switch to the page tables..
	set_cr3_raw((uintptr_t)ID_MAP_VTOP(IdlePML4));

}


/*
 * vstart() is called in the natural mode (64bit for K64, 32 for K32)
 * on a set of bootstrap pagetables which use large, 2MB pages to map 
 * all of physical memory in both. See idle_pt.c for details.
 *
 * In K64 this identity mapping is mirrored the top and bottom 512GB 
 * slots of PML4.
 *
 * The bootstrap processor called with argument boot_args_start pointing to
 * the boot-args block. The kernel's (4K page) page tables are allocated and
 * initialized before switching to these.
 *
 * Non-bootstrap processors are called with argument boot_args_start NULL.
 * These processors switch immediately to the existing kernel page tables.
 */
void
vstart(vm_offset_t boot_args_start)
{
	boolean_t	is_boot_cpu = !(boot_args_start == 0);
	int		cpu;
	uint32_t	lphysfree;

	postcode(VSTART_ENTRY);

	if (is_boot_cpu) {
		/*
		 * Get startup parameters.
		 */
		kernelBootArgs = (boot_args *)boot_args_start;
		lphysfree = kernelBootArgs->kaddr + kernelBootArgs->ksize;
		physfree = (void *)(uintptr_t)((lphysfree + PAGE_SIZE - 1) &~ (PAGE_SIZE - 1));

#if DEVELOPMENT || DEBUG
		pal_serial_init();
#endif
		DBG("revision      0x%x\n", kernelBootArgs->Revision);
		DBG("version       0x%x\n", kernelBootArgs->Version);
		DBG("command line  %s\n", kernelBootArgs->CommandLine);
		DBG("memory map    0x%x\n", kernelBootArgs->MemoryMap);
		DBG("memory map sz 0x%x\n", kernelBootArgs->MemoryMapSize);
		DBG("kaddr         0x%x\n", kernelBootArgs->kaddr);
		DBG("ksize         0x%x\n", kernelBootArgs->ksize);
		DBG("physfree      %p\n", physfree);
		DBG("bootargs: %p, &ksize: %p &kaddr: %p\n",
			kernelBootArgs, 
			&kernelBootArgs->ksize,
			&kernelBootArgs->kaddr);
		DBG("SMBIOS mem sz 0x%llx\n", kernelBootArgs->PhysicalMemorySize);

		/*
		 * Setup boot args given the physical start address.
		 * Note: PE_init_platform needs to be called before Idle_PTs_init
		 * because access to the DeviceTree is required to read the
		 * random seed before generating a random physical map slide.
		 */
		kernelBootArgs = (boot_args *)
		    ml_static_ptovirt(boot_args_start);
		DBG("i386_init(0x%lx) kernelBootArgs=%p\n",
		    (unsigned long)boot_args_start, kernelBootArgs);
		PE_init_platform(FALSE, kernelBootArgs);
		postcode(PE_INIT_PLATFORM_D);

		Idle_PTs_init();
		postcode(VSTART_IDLE_PTS_INIT);

		first_avail = (vm_offset_t)ID_MAP_VTOP(physfree);

		cpu = 0;
		cpu_data_alloc(TRUE);
	} else {
		/* Switch to kernel's page tables (from the Boot PTs) */
		set_cr3_raw((uintptr_t)ID_MAP_VTOP(IdlePML4));
		/* Find our logical cpu number */
		cpu = lapic_to_cpu[(LAPIC_READ(ID)>>LAPIC_ID_SHIFT) & LAPIC_ID_MASK];
		DBG("CPU: %d, GSBASE initial value: 0x%llx\n", cpu, rdmsr64(MSR_IA32_GS_BASE));
	}

	postcode(VSTART_CPU_DESC_INIT);
	if(is_boot_cpu)
		cpu_desc_init64(cpu_datap(cpu));
	cpu_desc_load64(cpu_datap(cpu));
	postcode(VSTART_CPU_MODE_INIT);
	if (is_boot_cpu)
		cpu_mode_init(current_cpu_datap()); /* cpu_mode_init() will be
						     * invoked on the APs
						     * via i386_init_slave()
						     */
	postcode(VSTART_EXIT);
	x86_init_wrapper(is_boot_cpu ? (uintptr_t) i386_init
				     : (uintptr_t) i386_init_slave,
			 cpu_datap(cpu)->cpu_int_stack_top);
}

void
pstate_trace(void)
{
}

/*
 *	Cpu initialization.  Running virtual, but without MACH VM
 *	set up.
 */
void
i386_init(void)
{
	unsigned int	maxmem;
	uint64_t	maxmemtouse;
	unsigned int	cpus = 0;
	boolean_t	fidn;
	boolean_t	IA32e = TRUE;

	postcode(I386_INIT_ENTRY);

	pal_i386_init();
	tsc_init();
	rtclock_early_init();	/* mach_absolute_time() now functionsl */

	kernel_debug_string_simple("i386_init");
	pstate_trace();

#if CONFIG_MCA
	/* Initialize machine-check handling */
	mca_cpu_init();
#endif

	master_cpu = 0;
	cpu_init();

	postcode(CPU_INIT_D);

	printf_init();			/* Init this in case we need debugger */
	panic_init();			/* Init this in case we need debugger */

	/* setup debugging output if one has been chosen */
	kernel_debug_string_simple("PE_init_kprintf");
	PE_init_kprintf(FALSE);

	kernel_debug_string_simple("kernel_early_bootstrap");
	kernel_early_bootstrap();

	if (!PE_parse_boot_argn("diag", &dgWork.dgFlags, sizeof (dgWork.dgFlags)))
		dgWork.dgFlags = 0;

	serialmode = 0;
	if(PE_parse_boot_argn("serial", &serialmode, sizeof (serialmode))) {
		/* We want a serial keyboard and/or console */
		kprintf("Serial mode specified: %08X\n", serialmode);
	}
	if(serialmode & 1) {
		(void)switch_to_serial_console();
		disableConsoleOutput = FALSE;	/* Allow printfs to happen */
	}

	/* setup console output */
	kernel_debug_string_simple("PE_init_printf");
	PE_init_printf(FALSE);

	kprintf("version_variant = %s\n", version_variant);
	kprintf("version         = %s\n", version);
	
	if (!PE_parse_boot_argn("maxmem", &maxmem, sizeof (maxmem)))
		maxmemtouse = 0;
	else
	        maxmemtouse = ((uint64_t)maxmem) * MB;

	if (PE_parse_boot_argn("cpus", &cpus, sizeof (cpus))) {
		if ((0 < cpus) && (cpus < max_ncpus))
                        max_ncpus = cpus;
	}

	/*
	 * debug support for > 4G systems
	 */
	PE_parse_boot_argn("himemory_mode", &vm_himemory_mode, sizeof (vm_himemory_mode));
	if (vm_himemory_mode != 0)
		kprintf("himemory_mode: %d\n", vm_himemory_mode);

	if (!PE_parse_boot_argn("immediate_NMI", &fidn, sizeof (fidn)))
		force_immediate_debugger_NMI = FALSE;
	else
		force_immediate_debugger_NMI = fidn;

#if DEBUG
	nanoseconds_to_absolutetime(URGENCY_NOTIFICATION_ASSERT_NS, &urgency_notification_assert_abstime_threshold);
#endif
	PE_parse_boot_argn("urgency_notification_abstime",
	    &urgency_notification_assert_abstime_threshold,
	    sizeof(urgency_notification_assert_abstime_threshold));

	if (!(cpuid_extfeatures() & CPUID_EXTFEATURE_XD))
		nx_enabled = 0;

	/*   
	 * VM initialization, after this we're using page tables...
	 * Thn maximum number of cpus must be set beforehand.
	 */
	kernel_debug_string_simple("i386_vm_init");
	i386_vm_init(maxmemtouse, IA32e, kernelBootArgs);

	/* create the console for verbose or pretty mode */
	/* Note: doing this prior to tsc_init() allows for graceful panic! */
	PE_init_platform(TRUE, kernelBootArgs);
	PE_create_console();

	kernel_debug_string_simple("power_management_init");
	power_management_init();
	processor_bootstrap();
	thread_bootstrap();

	pstate_trace();
	kernel_debug_string_simple("machine_startup");
	machine_startup();
	pstate_trace();
}

static void
do_init_slave(boolean_t fast_restart)
{
	void	*init_param	= FULL_SLAVE_INIT;

	postcode(I386_INIT_SLAVE);

	if (!fast_restart) {
		/* Ensure that caching and write-through are enabled */
		set_cr0(get_cr0() & ~(CR0_NW|CR0_CD));
  
		DBG("i386_init_slave() CPU%d: phys (%d) active.\n",
		    get_cpu_number(), get_cpu_phys_number());
  
		assert(!ml_get_interrupts_enabled());
  
		cpu_mode_init(current_cpu_datap());
		pmap_cpu_init();
  
#if CONFIG_MCA
		mca_cpu_init();
#endif
  
		LAPIC_INIT();
		lapic_configure();
		LAPIC_DUMP();
		LAPIC_CPU_MAP_DUMP();
  
		init_fpu();
  
#if CONFIG_MTRR
		mtrr_update_cpu();
#endif
		/* update CPU microcode */
		ucode_update_wake();
	} else
	    init_param = FAST_SLAVE_INIT;

#if CONFIG_VMX
	/* resume VT operation */
	vmx_resume();
#endif

#if CONFIG_MTRR
	if (!fast_restart)
	    pat_init();
#endif

	cpu_thread_init();	/* not strictly necessary */

	cpu_init();	/* Sets cpu_running which starter cpu waits for */
 	slave_main(init_param);
  
 	panic("do_init_slave() returned from slave_main()");
}

/*
 * i386_init_slave() is called from pstart.
 * We're in the cpu's interrupt stack with interrupts disabled.
 * At this point we are in legacy mode. We need to switch on IA32e
 * if the mode is set to 64-bits.
 */
void
i386_init_slave(void)
{
    	do_init_slave(FALSE);
}

/*
 * i386_init_slave_fast() is called from pmCPUHalt.
 * We're running on the idle thread and need to fix up
 * some accounting and get it so that the scheduler sees this
 * CPU again.
 */
void
i386_init_slave_fast(void)
{
    	do_init_slave(TRUE);
}


