/*
 * Copyright (c) 2003-2019 Apple Inc. All rights reserved.
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
#include <stdint.h>
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

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

#include <san/kasan.h>

#if DEBUG
#define DBG(x ...)       kprintf(x)
#else
#define DBG(x ...)
#endif

int                     debug_task;

int                     early_boot = 1;

static boot_args        *kernelBootArgs;

extern int              disableConsoleOutput;
extern const char       version[];
extern const char       version_variant[];
extern int              nx_enabled;

/*
 * Set initial values so that ml_phys_* routines can use the booter's ID mapping
 * to touch physical space before the kernel's physical aperture exists.
 */
uint64_t                physmap_base = 0;
uint64_t                physmap_max = 4 * GB;

pd_entry_t              *KPTphys;
pd_entry_t              *IdlePTD;
pdpt_entry_t            *IdlePDPT;
pml4_entry_t            *IdlePML4;

int                     kernPhysPML4Index;
int                     kernPhysPML4EntryCount;

/*
 * These are 4K mapping page table pages from KPTphys[] that we wound
 * up not using. They get ml_static_mfree()'d once the VM is initialized.
 */
ppnum_t                 released_PT_ppn = 0;
uint32_t                released_PT_cnt = 0;

char *physfree;
void idt64_remap(void);

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
	for (i = 0; i < count; i++) {
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

static int
physmap_init_L2(uint64_t *physStart, pt_entry_t **l2ptep)
{
	unsigned i;
	pt_entry_t *physmapL2 = ALLOCPAGES(1);

	if (physmapL2 == NULL) {
		DBG("physmap_init_L2 page alloc failed when initting L2 for physAddr 0x%llx.\n", *physStart);
		*l2ptep = NULL;
		return -1;
	}

	for (i = 0; i < NPDPG; i++) {
		physmapL2[i] = *physStart
		    | INTEL_PTE_PS
		    | INTEL_PTE_VALID
		    | INTEL_PTE_NX
		    | INTEL_PTE_WRITE;

		*physStart += NBPD;
	}
	*l2ptep = physmapL2;
	return 0;
}

static int
physmap_init_L3(int startIndex, uint64_t highest_phys, uint64_t *physStart, pt_entry_t **l3ptep)
{
	unsigned i;
	int ret;
	pt_entry_t *l2pte;
	pt_entry_t *physmapL3 = ALLOCPAGES(1);  /* ALLOCPAGES bzeroes the memory */

	if (physmapL3 == NULL) {
		DBG("physmap_init_L3 page alloc failed when initting L3 for  physAddr 0x%llx.\n", *physStart);
		*l3ptep = NULL;
		return -1;
	}

	for (i = startIndex; i < NPDPTPG && *physStart < highest_phys; i++) {
		if ((ret = physmap_init_L2(physStart, &l2pte)) < 0) {
			return ret;
		}

		physmapL3[i] =  ((uintptr_t)ID_MAP_VTOP(l2pte))
		    | INTEL_PTE_VALID
		    | INTEL_PTE_NX
		    | INTEL_PTE_WRITE;
	}

	*l3ptep = physmapL3;

	return 0;
}

static void
physmap_init(uint8_t phys_random_L3, uint64_t *new_physmap_base, uint64_t *new_physmap_max)
{
	pt_entry_t *l3pte;
	int pml4_index, i;
	int L3_start_index;
	uint64_t physAddr = 0;
	uint64_t highest_physaddr;
	unsigned pdpte_count;

#if DEVELOPMENT || DEBUG
	if (kernelBootArgs->PhysicalMemorySize > K64_MAXMEM) {
		panic("Installed physical memory exceeds configured maximum.");
	}
#endif

	/*
	 * Add 4GB to the loader-provided physical memory size to account for MMIO space
	 * XXX in a perfect world, we'd scan PCI buses and count the max memory requested in BARs by
	 * XXX all enumerated device, then add more for hot-pluggable devices.
	 */
	highest_physaddr = kernelBootArgs->PhysicalMemorySize + 4 * GB;

	/*
	 * Calculate the number of PML4 entries we'll need.  The total number of entries is
	 * pdpte_count = (((highest_physaddr) >> PDPT_SHIFT) + entropy_value +
	 *               ((highest_physaddr & PDPT_MASK) == 0 ? 0 : 1))
	 * pml4e_count = pdpte_count >> (PML4_SHIFT - PDPT_SHIFT)
	 */
	assert(highest_physaddr < (UINT64_MAX - PDPTMASK));
	pdpte_count = (unsigned) (((highest_physaddr + PDPTMASK) >> PDPTSHIFT) + phys_random_L3);
	kernPhysPML4EntryCount = (pdpte_count + ((1U << (PML4SHIFT - PDPTSHIFT)) - 1)) >> (PML4SHIFT - PDPTSHIFT);
	if (kernPhysPML4EntryCount == 0) {
		kernPhysPML4EntryCount = 1;
	}
	if (kernPhysPML4EntryCount > KERNEL_PHYSMAP_PML4_COUNT_MAX) {
#if DEVELOPMENT || DEBUG
		panic("physmap too large");
#else
		kprintf("[pmap] Limiting physmap to %d PML4s (was %d)\n", KERNEL_PHYSMAP_PML4_COUNT_MAX,
		    kernPhysPML4EntryCount);
		kernPhysPML4EntryCount = KERNEL_PHYSMAP_PML4_COUNT_MAX;
#endif
	}

	kernPhysPML4Index = KERNEL_KEXTS_INDEX - kernPhysPML4EntryCount;        /* utb: KERNEL_PHYSMAP_PML4_INDEX */

	/*
	 * XXX: Make sure that the addresses returned for physmapL3 and physmapL2 plus their extents
	 * are in the system-available memory range
	 */


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

	L3_start_index = phys_random_L3;

	for (pml4_index = kernPhysPML4Index;
	    pml4_index < (kernPhysPML4Index + kernPhysPML4EntryCount) && physAddr < highest_physaddr;
	    pml4_index++) {
		if (physmap_init_L3(L3_start_index, highest_physaddr, &physAddr, &l3pte) < 0) {
			panic("Physmap page table initialization failed");
			/* NOTREACHED */
		}

		L3_start_index = 0;

		IdlePML4[pml4_index] = ((uintptr_t)ID_MAP_VTOP(l3pte))
		    | INTEL_PTE_VALID
		    | INTEL_PTE_NX
		    | INTEL_PTE_WRITE;
	}

	*new_physmap_base = KVADDR(kernPhysPML4Index, phys_random_L3, 0, 0);
	/*
	 * physAddr contains the last-mapped physical address, so that's what we
	 * add to physmap_base to derive the ending VA for the physmap.
	 */
	*new_physmap_max = *new_physmap_base + physAddr;

	DBG("Physical address map base: 0x%qx\n", *new_physmap_base);
	for (i = kernPhysPML4Index; i < (kernPhysPML4Index + kernPhysPML4EntryCount); i++) {
		DBG("Physical map idlepml4[%d]: 0x%llx\n", i, IdlePML4[i]);
	}
}

void doublemap_init(uint8_t);

static void
Idle_PTs_init(void)
{
	uint64_t        rand64;
	uint64_t        new_physmap_base, new_physmap_max;

	/* Allocate the "idle" kernel page tables: */
	KPTphys  = ALLOCPAGES(NKPT);            /* level 1 */
	IdlePTD  = ALLOCPAGES(NPGPTD);          /* level 2 */
	IdlePDPT = ALLOCPAGES(1);               /* level 3 */
	IdlePML4 = ALLOCPAGES(1);               /* level 4 */

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

	/*
	 * early_random() cannot be called more than one time before the cpu's
	 * gsbase is initialized, so use the full 64-bit value to extract the
	 * two 8-bit entropy values needed for address randomization.
	 */
	rand64 = early_random();
	physmap_init(rand64 & 0xFF, &new_physmap_base, &new_physmap_max);
	doublemap_init((rand64 >> 8) & 0xFF);
	idt64_remap();

	postcode(VSTART_SET_CR3);

	/*
	 * Switch to the page tables. We set physmap_base and physmap_max just
	 * before switching to the new page tables to avoid someone calling
	 * kprintf() or otherwise using physical memory in between.
	 * This is needed because kprintf() writes to physical memory using
	 * ml_phys_read_data and PHYSMAP_PTOV, which requires physmap_base to be
	 * set correctly.
	 */
	physmap_base = new_physmap_base;
	physmap_max = new_physmap_max;
	set_cr3_raw((uintptr_t)ID_MAP_VTOP(IdlePML4));
}

/*
 * Release any still unused, preallocated boot kernel page tables.
 * start..end is the VA range currently unused.
 */
void
Idle_PTs_release(vm_offset_t start, vm_offset_t end)
{
	uint32_t i;
	uint32_t index_start;
	uint32_t index_limit;
	ppnum_t pn_first;
	ppnum_t pn;
	uint32_t cnt;

	/*
	 * Align start to the next large page boundary
	 */
	start = ((start + I386_LPGMASK) & ~I386_LPGMASK);

	/*
	 * convert start into an index in KPTphys[]
	 */
	index_start = (uint32_t)((start - KERNEL_BASE) >> PAGE_SHIFT);

	/*
	 * Find the ending index in KPTphys[]
	 */
	index_limit = (uint32_t)((end - KERNEL_BASE) >> PAGE_SHIFT);

	if (index_limit > NKPT * PTE_PER_PAGE) {
		index_limit = NKPT * PTE_PER_PAGE;
	}

	/*
	 * Make sure all the 4K page tables are empty.
	 * If not, panic a development/debug kernel.
	 * On a production kernel, since this would stop us from booting,
	 * just abort the operation.
	 */
	for (i = index_start; i < index_limit; ++i) {
		assert(KPTphys[i] == 0);
		if (KPTphys[i] != 0) {
			return;
		}
	}

	/*
	 * Now figure out the indices into the 2nd level page tables, IdlePTD[].
	 */
	index_start >>= PTPGSHIFT;
	index_limit >>= PTPGSHIFT;
	if (index_limit > NPGPTD * PTE_PER_PAGE) {
		index_limit = NPGPTD * PTE_PER_PAGE;
	}

	if (index_limit <= index_start) {
		return;
	}


	/*
	 * Now check the pages referenced from Level 2 tables.
	 * They should be contiguous, assert fail if not on development/debug.
	 * In production, just fail the removal to allow the system to boot.
	 */
	pn_first = 0;
	cnt = 0;
	for (i = index_start; i < index_limit; ++i) {
		assert(IdlePTD[i] != 0);
		if (IdlePTD[i] == 0) {
			return;
		}

		pn = (ppnum_t)((PG_FRAME & IdlePTD[i]) >> PTSHIFT);
		if (cnt == 0) {
			pn_first = pn;
		} else {
			assert(pn == pn_first + cnt);
			if (pn != pn_first + cnt) {
				return;
			}
		}
		++cnt;
	}

	/*
	 * Good to go, clear the level 2 entries and invalidate the TLB
	 */
	for (i = index_start; i < index_limit; ++i) {
		IdlePTD[i] = 0;
	}
	set_cr3_raw(get_cr3_raw());

	/*
	 * Remember these PFNs to be released later in pmap_lowmem_finalize()
	 */
	released_PT_ppn = pn_first;
	released_PT_cnt = cnt;
#if DEVELOPMENT || DEBUG
	printf("Idle_PTs_release %d pages from PFN 0x%x\n", released_PT_cnt, released_PT_ppn);
#endif
}

extern void vstart_trap_handler;

#define BOOT_TRAP_VECTOR(t)                             \
	[t] = {                                         \
	        (uintptr_t) &vstart_trap_handler,       \
	        KERNEL64_CS,                            \
	        0,                                      \
	        ACC_P|ACC_PL_K|ACC_INTR_GATE,           \
	        0                                       \
	},

/* Recursive macro to iterate 0..31 */
#define L0(x, n)  x(n)
#define L1(x, n)  L0(x,n-1)     L0(x,n)
#define L2(x, n)  L1(x,n-2)     L1(x,n)
#define L3(x, n)  L2(x,n-4)     L2(x,n)
#define L4(x, n)  L3(x,n-8)     L3(x,n)
#define L5(x, n)  L4(x,n-16)    L4(x,n)
#define FOR_0_TO_31(x) L5(x,31)

/*
 * Bootstrap IDT. Active only during early startup.
 * Only the trap vectors are defined since interrupts are masked.
 * All traps point to a common handler.
 */
struct fake_descriptor64 master_boot_idt64[IDTSZ]
__attribute__((section("__HIB,__desc")))
__attribute__((aligned(PAGE_SIZE))) = {
	FOR_0_TO_31(BOOT_TRAP_VECTOR)
};

static void
vstart_idt_init(void)
{
	x86_64_desc_register_t  vstart_idt = {
		sizeof(master_boot_idt64),
		master_boot_idt64
	};

	fix_desc64(master_boot_idt64, 32);
	lidt((void *)&vstart_idt);
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
__attribute__((noreturn))
void
vstart(vm_offset_t boot_args_start)
{
	boolean_t       is_boot_cpu = !(boot_args_start == 0);
	int             cpu = 0;
	uint32_t        lphysfree;
#if DEBUG
	uint64_t        gsbase;
#endif


	postcode(VSTART_ENTRY);

	if (is_boot_cpu) {
		/*
		 * Set-up temporary trap handlers during page-table set-up.
		 */
		vstart_idt_init();
		postcode(VSTART_IDT_INIT);

		/*
		 * Ensure that any %gs-relative access results in an immediate fault
		 * until gsbase is properly initialized below
		 */
		wrmsr64(MSR_IA32_GS_BASE, EARLY_GSBASE_MAGIC);

		/*
		 * Get startup parameters.
		 */
		kernelBootArgs = (boot_args *)boot_args_start;
		lphysfree = kernelBootArgs->kaddr + kernelBootArgs->ksize;
		physfree = (void *)(uintptr_t)((lphysfree + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

		pal_serial_init();

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

#if KASAN
		kasan_reserve_memory(kernelBootArgs);
#endif

		PE_init_platform(FALSE, kernelBootArgs);
		postcode(PE_INIT_PLATFORM_D);

		Idle_PTs_init();
		postcode(VSTART_IDLE_PTS_INIT);

#if KASAN
		/* Init kasan and map whatever was stolen from physfree */
		kasan_init();
		kasan_notify_stolen((uintptr_t)ml_static_ptovirt((vm_offset_t)physfree));
#endif

#if MONOTONIC
		mt_early_init();
#endif /* MONOTONIC */

		first_avail = (vm_offset_t)ID_MAP_VTOP(physfree);

		cpu_data_alloc(TRUE);

		cpu_desc_init(cpu_datap(0));
		postcode(VSTART_CPU_DESC_INIT);
		cpu_desc_load(cpu_datap(0));

		postcode(VSTART_CPU_MODE_INIT);
		cpu_syscall_init(cpu_datap(0)); /* cpu_syscall_init() will be
		                                 * invoked on the APs
		                                 * via i386_init_slave()
		                                 */
	} else {
		/* Switch to kernel's page tables (from the Boot PTs) */
		set_cr3_raw((uintptr_t)ID_MAP_VTOP(IdlePML4));
		/* Find our logical cpu number */
		cpu = lapic_to_cpu[(LAPIC_READ(ID) >> LAPIC_ID_SHIFT) & LAPIC_ID_MASK];
#if DEBUG
		gsbase = rdmsr64(MSR_IA32_GS_BASE);
#endif
		cpu_desc_load(cpu_datap(cpu));
		DBG("CPU: %d, GSBASE initial value: 0x%llx\n", cpu, gsbase);
	}

	early_boot = 0;
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
	unsigned int    maxmem;
	uint64_t        maxmemtouse;
	unsigned int    cpus = 0;
	boolean_t       fidn;
	boolean_t       IA32e = TRUE;

	postcode(I386_INIT_ENTRY);

	pal_i386_init();
	tsc_init();
	rtclock_early_init();   /* mach_absolute_time() now functionsl */

	kernel_debug_string_early("i386_init");
	pstate_trace();

#if CONFIG_MCA
	/* Initialize machine-check handling */
	mca_cpu_init();
#endif

	master_cpu = 0;

	lck_mod_init();

	printf_init();                  /* Init this in case we need debugger */

	/*
	 * Initialize the timer callout world
	 */
	timer_call_init();

	cpu_init();

	postcode(CPU_INIT_D);

	panic_init();                   /* Init this in case we need debugger */

	/* setup debugging output if one has been chosen */
	kernel_debug_string_early("PE_init_kprintf");
	PE_init_kprintf(FALSE);

	kernel_debug_string_early("kernel_early_bootstrap");
	kernel_early_bootstrap();

	if (!PE_parse_boot_argn("diag", &dgWork.dgFlags, sizeof(dgWork.dgFlags))) {
		dgWork.dgFlags = 0;
	}

	serialmode = 0;
	if (PE_parse_boot_argn("serial", &serialmode, sizeof(serialmode))) {
		/* We want a serial keyboard and/or console */
		kprintf("Serial mode specified: %08X\n", serialmode);
		int force_sync = serialmode & SERIALMODE_SYNCDRAIN;
		if (force_sync || PE_parse_boot_argn("drain_uart_sync", &force_sync, sizeof(force_sync))) {
			if (force_sync) {
				serialmode |= SERIALMODE_SYNCDRAIN;
				kprintf(
					"WARNING: Forcing uart driver to output synchronously."
					"printf()s/IOLogs will impact kernel performance.\n"
					"You are advised to avoid using 'drain_uart_sync' boot-arg.\n");
			}
		}
	}
	if (serialmode & SERIALMODE_OUTPUT) {
		(void)switch_to_serial_console();
		disableConsoleOutput = FALSE; /* Allow printfs to happen */
	}

	/* setup console output */
	kernel_debug_string_early("PE_init_printf");
	PE_init_printf(FALSE);

	kprintf("version_variant = %s\n", version_variant);
	kprintf("version         = %s\n", version);

	if (!PE_parse_boot_argn("maxmem", &maxmem, sizeof(maxmem))) {
		maxmemtouse = 0;
	} else {
		maxmemtouse = ((uint64_t)maxmem) * MB;
	}

	if (PE_parse_boot_argn("cpus", &cpus, sizeof(cpus))) {
		if ((0 < cpus) && (cpus < max_ncpus)) {
			max_ncpus = cpus;
		}
	}

	/*
	 * debug support for > 4G systems
	 */
	PE_parse_boot_argn("himemory_mode", &vm_himemory_mode, sizeof(vm_himemory_mode));
	if (!vm_himemory_mode) {
		kprintf("himemory_mode disabled\n");
	}

	if (!PE_parse_boot_argn("immediate_NMI", &fidn, sizeof(fidn))) {
		force_immediate_debugger_NMI = FALSE;
	} else {
		force_immediate_debugger_NMI = fidn;
	}

#if DEBUG
	nanoseconds_to_absolutetime(URGENCY_NOTIFICATION_ASSERT_NS, &urgency_notification_assert_abstime_threshold);
#endif
	PE_parse_boot_argn("urgency_notification_abstime",
	    &urgency_notification_assert_abstime_threshold,
	    sizeof(urgency_notification_assert_abstime_threshold));

	if (!(cpuid_extfeatures() & CPUID_EXTFEATURE_XD)) {
		nx_enabled = 0;
	}

	/*
	 * VM initialization, after this we're using page tables...
	 * Thn maximum number of cpus must be set beforehand.
	 */
	kernel_debug_string_early("i386_vm_init");
	i386_vm_init(maxmemtouse, IA32e, kernelBootArgs);

	/* create the console for verbose or pretty mode */
	/* Note: doing this prior to tsc_init() allows for graceful panic! */
	PE_init_platform(TRUE, kernelBootArgs);
	PE_create_console();

	kernel_debug_string_early("power_management_init");
	power_management_init();

#if MONOTONIC
	mt_cpu_up(cpu_datap(0));
#endif /* MONOTONIC */

	processor_bootstrap();
	thread_t thread = thread_bootstrap();
	machine_set_current_thread(thread);

	pstate_trace();
	kernel_debug_string_early("machine_startup");
	machine_startup();
	pstate_trace();
}

static void __dead2
do_init_slave(boolean_t fast_restart)
{
	void    *init_param     = FULL_SLAVE_INIT;

	postcode(I386_INIT_SLAVE);

	if (!fast_restart) {
		/* Ensure that caching and write-through are enabled */
		set_cr0(get_cr0() & ~(CR0_NW | CR0_CD));

		DBG("i386_init_slave() CPU%d: phys (%d) active.\n",
		    get_cpu_number(), get_cpu_phys_number());

		assert(!ml_get_interrupts_enabled());

		cpu_syscall_init(current_cpu_datap());
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
	} else {
		init_param = FAST_SLAVE_INIT;
	}

#if CONFIG_VMX
	/* resume VT operation */
	vmx_resume(FALSE);
#endif

#if CONFIG_MTRR
	if (!fast_restart) {
		pat_init();
	}
#endif

	cpu_thread_init();      /* not strictly necessary */

	cpu_init();     /* Sets cpu_running which starter cpu waits for */


#if MONOTONIC
	mt_cpu_up(current_cpu_datap());
#endif /* MONOTONIC */

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

#include <libkern/kernel_mach_header.h>

/* TODO: Evaluate global PTEs for the double-mapped translations */

uint64_t dblmap_base, dblmap_max;
kernel_segment_command_t *hdescseg;

pt_entry_t *dblmapL3;
unsigned int dblallocs;
uint64_t dblmap_dist;
extern uint64_t idt64_hndl_table0[];


void
doublemap_init(uint8_t randL3)
{
	dblmapL3 = ALLOCPAGES(1); // for 512 1GiB entries
	dblallocs++;

	struct {
		pt_entry_t entries[PTE_PER_PAGE];
	} * dblmapL2 = ALLOCPAGES(1); // for 512 2MiB entries
	dblallocs++;

	dblmapL3[randL3] = ((uintptr_t)ID_MAP_VTOP(&dblmapL2[0]))
	    | INTEL_PTE_VALID
	    | INTEL_PTE_WRITE;

	hdescseg = getsegbynamefromheader(&_mh_execute_header, "__HIB");

	vm_offset_t hdescb = hdescseg->vmaddr;
	unsigned long hdescsz = hdescseg->vmsize;
	unsigned long hdescszr = round_page_64(hdescsz);
	vm_offset_t hdescc = hdescb, hdesce = hdescb + hdescszr;

	kernel_section_t *thdescsect = getsectbynamefromheader(&_mh_execute_header, "__HIB", "__text");
	vm_offset_t thdescb = thdescsect->addr;
	unsigned long thdescsz = thdescsect->size;
	unsigned long thdescszr = round_page_64(thdescsz);
	vm_offset_t thdesce = thdescb + thdescszr;

	assert((hdescb & 0xFFF) == 0);
	/* Mirror HIB translations into the double-mapped pagetable subtree*/
	for (int i = 0; hdescc < hdesce; i++) {
		struct {
			pt_entry_t entries[PTE_PER_PAGE];
		} * dblmapL1 = ALLOCPAGES(1);
		dblallocs++;
		dblmapL2[0].entries[i] = ((uintptr_t)ID_MAP_VTOP(&dblmapL1[0])) | INTEL_PTE_VALID | INTEL_PTE_WRITE | INTEL_PTE_REF;
		int hdescn = (int) ((hdesce - hdescc) / PAGE_SIZE);
		for (int j = 0; j < MIN(PTE_PER_PAGE, hdescn); j++) {
			uint64_t template = INTEL_PTE_VALID;
			if ((hdescc >= thdescb) && (hdescc < thdesce)) {
				/* executable */
			} else {
				template |= INTEL_PTE_WRITE | INTEL_PTE_NX;  /* Writeable, NX */
			}
			dblmapL1[0].entries[j] = ((uintptr_t)ID_MAP_VTOP(hdescc)) | template;
			hdescc += PAGE_SIZE;
		}
	}

	IdlePML4[KERNEL_DBLMAP_PML4_INDEX] = ((uintptr_t)ID_MAP_VTOP(dblmapL3)) | INTEL_PTE_VALID | INTEL_PTE_WRITE | INTEL_PTE_REF;

	dblmap_base = KVADDR(KERNEL_DBLMAP_PML4_INDEX, randL3, 0, 0);
	dblmap_max = dblmap_base + hdescszr;
	/* Calculate the double-map distance, which accounts for the current
	 * KASLR slide
	 */

	dblmap_dist = dblmap_base - hdescb;
	idt64_hndl_table0[1] = DBLMAP(idt64_hndl_table0[1]);    /* 64-bit exit trampoline */
	idt64_hndl_table0[3] = DBLMAP(idt64_hndl_table0[3]);    /* 32-bit exit trampoline */
	idt64_hndl_table0[6] = (uint64_t)(uintptr_t)&kernel_stack_mask;

	extern cpu_data_t cpshadows[], scdatas[];
	uintptr_t cd1 = (uintptr_t) &cpshadows[0];
	uintptr_t cd2 = (uintptr_t) &scdatas[0];
/* Record the displacement from the kernel's per-CPU data pointer, eventually
 * programmed into GSBASE, to the "shadows" in the doublemapped
 * region. These are not aliases, but separate physical allocations
 * containing data required in the doublemapped trampolines.
 */
	idt64_hndl_table0[2] = dblmap_dist + cd1 - cd2;

	DBG("Double map base: 0x%qx\n", dblmap_base);
	DBG("double map idlepml4[%d]: 0x%llx\n", KERNEL_DBLMAP_PML4_INDEX, IdlePML4[KERNEL_DBLMAP_PML4_INDEX]);
	assert(LDTSZ > LDTSZ_MIN);
}

vm_offset_t dyn_dblmap(vm_offset_t, vm_offset_t);

#include <i386/pmap_internal.h>

/* Use of this routine is expected to be synchronized by callers
 * Creates non-executable aliases.
 */
vm_offset_t
dyn_dblmap(vm_offset_t cva, vm_offset_t sz)
{
	vm_offset_t ava = dblmap_max;

	assert((sz & PAGE_MASK) == 0);
	assert(cva != 0);

	pmap_alias(ava, cva, cva + sz, VM_PROT_READ | VM_PROT_WRITE, PMAP_EXPAND_OPTIONS_ALIASMAP);
	dblmap_max += sz;
	return ava - cva;
}
/* Adjust offsets interior to the bootstrap interrupt descriptor table to redirect
 * control to the double-mapped interrupt vectors. The IDTR proper will be
 * programmed via cpu_desc_load()
 */
void
idt64_remap(void)
{
	for (int i = 0; i < IDTSZ; i++) {
		master_idt64[i].offset64 = DBLMAP(master_idt64[i].offset64);
	}
}
