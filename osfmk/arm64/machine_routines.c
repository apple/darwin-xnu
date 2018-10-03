/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
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

#include <arm64/proc_reg.h>
#include <arm/machine_cpu.h>
#include <arm/cpu_internal.h>
#include <arm/cpuid.h>
#include <arm/io_map_entries.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/caches_internal.h>
#include <arm/misc_protos.h>
#include <arm/machdep_call.h>
#include <arm/rtclock.h>
#include <console/serial_protos.h>
#include <kern/machine.h>
#include <prng/random.h>
#include <kern/startup.h>
#include <kern/thread.h>
#include <mach/machine.h>
#include <machine/atomic.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <sys/kdebug.h>
#include <kern/coalition.h>
#include <pexpert/device_tree.h>

#include <IOKit/IOPlatformExpert.h>

#if defined(KERNEL_INTEGRITY_KTRR)
#include <libkern/kernel_mach_header.h>
#endif

#if KPC
#include <kern/kpc.h>
#endif


static int max_cpus_initialized = 0;
#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

uint32_t LockTimeOut;
uint32_t LockTimeOutUsec;
uint64_t MutexSpin;
boolean_t is_clock_configured = FALSE;

extern int mach_assert;
extern volatile uint32_t debug_enabled;


void machine_conf(void);

thread_t Idle_context(void);

static uint32_t cpu_phys_ids[MAX_CPUS] = {[0 ... MAX_CPUS - 1] = (uint32_t)-1};
static unsigned int avail_cpus = 0;
static int boot_cpu = -1;
static int max_cpu_number = 0;
cluster_type_t boot_cluster = CLUSTER_TYPE_SMP;

lockdown_handler_t lockdown_handler;
void *lockdown_this;
lck_mtx_t lockdown_handler_lck;
lck_grp_t *lockdown_handler_grp;
int lockdown_done;

void ml_lockdown_init(void);
void ml_lockdown_run_handler(void);
uint32_t get_arm_cpu_version(void);


void ml_cpu_signal(unsigned int cpu_id __unused)
{
	panic("Platform does not support ACC Fast IPI");
}

void ml_cpu_signal_deferred_adjust_timer(uint64_t nanosecs) {
	(void)nanosecs;
	panic("Platform does not support ACC Fast IPI");
}

uint64_t ml_cpu_signal_deferred_get_timer() {
	return 0;
}

void ml_cpu_signal_deferred(unsigned int cpu_id __unused)
{
	panic("Platform does not support ACC Fast IPI deferral");
}

void ml_cpu_signal_retract(unsigned int cpu_id __unused)
{
	panic("Platform does not support ACC Fast IPI retraction");
}

void machine_idle(void)
{
	__asm__ volatile ("msr DAIFSet, %[mask]" ::[mask] "i" (DAIFSC_IRQF | DAIFSC_FIQF));
	Idle_context();
	__asm__ volatile ("msr DAIFClr, %[mask]" ::[mask] "i" (DAIFSC_IRQF | DAIFSC_FIQF));
}

void init_vfp(void)
{
	return;
}

boolean_t get_vfp_enabled(void)
{
	return TRUE;
}

void OSSynchronizeIO(void)
{
	__builtin_arm_dsb(DSB_SY);
}

uint64_t get_aux_control(void)
{
	uint64_t	value;

	MRS(value, "ACTLR_EL1");
	return value;
}

uint64_t get_mmu_control(void)
{
	uint64_t	value;

	MRS(value, "SCTLR_EL1");
	return value;
}

uint64_t get_tcr(void)
{
	uint64_t	value;

	MRS(value, "TCR_EL1");
	return value;
}

boolean_t ml_get_interrupts_enabled(void)
{
	uint64_t	value;

	MRS(value, "DAIF");
	if (value & DAIF_IRQF)
		return FALSE;
	return TRUE;
}

pmap_paddr_t get_mmu_ttb(void)
{
	pmap_paddr_t	value;

	MRS(value, "TTBR0_EL1");
	return value;
}

MARK_AS_PMAP_TEXT
void set_mmu_ttb(pmap_paddr_t value)
{
#if __ARM_KERNEL_PROTECT__
	/* All EL1-mode ASIDs are odd. */
	value |= (1ULL << TTBR_ASID_SHIFT);
#endif /* __ARM_KERNEL_PROTECT__ */

	__builtin_arm_dsb(DSB_ISH);
	MSR("TTBR0_EL1", value);
	__builtin_arm_isb(ISB_SY);
}

static uint32_t get_midr_el1(void)
{
	uint64_t value;

	MRS(value, "MIDR_EL1");

	/* This is a 32-bit register. */
	return (uint32_t) value;
}

uint32_t get_arm_cpu_version(void)
{
	uint32_t value = get_midr_el1();

	/* Compose the register values into 8 bits; variant[7:4], revision[3:0]. */
	return ((value & MIDR_EL1_REV_MASK) >> MIDR_EL1_REV_SHIFT) | ((value & MIDR_EL1_VAR_MASK) >> (MIDR_EL1_VAR_SHIFT - 4));
}

/*
 * user_cont_hwclock_allowed()
 *
 * Indicates whether we allow EL0 to read the physical timebase (CNTPCT_EL0)
 * as a continuous time source (e.g. from mach_continuous_time)
 */
boolean_t user_cont_hwclock_allowed(void)
{
	return FALSE;
}

/*
 * user_timebase_allowed()
 *
 * Indicates whether we allow EL0 to read the physical timebase (CNTPCT_EL0).
 */
boolean_t user_timebase_allowed(void)
{
	return TRUE;
}

boolean_t arm64_wfe_allowed(void)
{
	return TRUE;
}

#if defined(KERNEL_INTEGRITY_KTRR)

uint64_t rorgn_begin __attribute__((section("__DATA, __const"))) = 0;
uint64_t rorgn_end   __attribute__((section("__DATA, __const"))) = 0;
vm_offset_t amcc_base;

static void assert_unlocked(void);
static void assert_amcc_cache_disabled(void);
static void lock_amcc(void);
static void lock_mmu(uint64_t begin, uint64_t end);

void rorgn_stash_range(void)
{

#if DEVELOPMENT || DEBUG
	boolean_t rorgn_disable = FALSE;

	PE_parse_boot_argn("-unsafe_kernel_text", &rorgn_disable, sizeof(rorgn_disable));

	if (rorgn_disable) {
		/* take early out if boot arg present, don't query any machine registers to avoid
		 * dependency on amcc DT entry
		 */
		return;
	}
#endif

	/* Get the AMC values, and stash them into rorgn_begin, rorgn_end. */

#if defined(KERNEL_INTEGRITY_KTRR)
	uint64_t soc_base = 0;
	DTEntry entryP = NULL;
	uintptr_t *reg_prop = NULL;
	uint32_t prop_size = 0;
	int rc;

	soc_base = pe_arm_get_soc_base_phys();
	rc = DTFindEntry("name", "mcc", &entryP);
	assert(rc == kSuccess);
	rc = DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
	assert(rc == kSuccess);
	amcc_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
#else
#error "KERNEL_INTEGRITY config error"
#endif

#if defined(KERNEL_INTEGRITY_KTRR)
	assert(rRORGNENDADDR > rRORGNBASEADDR);
	rorgn_begin = (rRORGNBASEADDR << ARM_PGSHIFT) + gPhysBase;
	rorgn_end   = (rRORGNENDADDR << ARM_PGSHIFT) + gPhysBase;
#else
#error KERNEL_INTEGRITY config error
#endif /* defined (KERNEL_INTEGRITY_KTRR) */
}

static void assert_unlocked() {
	uint64_t ktrr_lock = 0;
	uint32_t rorgn_lock = 0;

	assert(amcc_base);
#if defined(KERNEL_INTEGRITY_KTRR)
	rorgn_lock = rRORGNLOCK;
	ktrr_lock = __builtin_arm_rsr64(ARM64_REG_KTRR_LOCK_EL1);
#else
#error KERNEL_INTEGRITY config error
#endif /* defined(KERNEL_INTEGRITY_KTRR) */

	assert(!ktrr_lock);
	assert(!rorgn_lock);
}

static void lock_amcc() {
#if defined(KERNEL_INTEGRITY_KTRR)
	rRORGNLOCK = 1;
	__builtin_arm_isb(ISB_SY);
#else
#error KERNEL_INTEGRITY config error
#endif
}

static void lock_mmu(uint64_t begin, uint64_t end) {

#if defined(KERNEL_INTEGRITY_KTRR)

	__builtin_arm_wsr64(ARM64_REG_KTRR_LOWER_EL1, begin);
	__builtin_arm_wsr64(ARM64_REG_KTRR_UPPER_EL1, end);
	__builtin_arm_wsr64(ARM64_REG_KTRR_LOCK_EL1,  1ULL);

	/* flush TLB */

	__builtin_arm_isb(ISB_SY);
	flush_mmu_tlb();

#else
#error KERNEL_INTEGRITY config error
#endif

}

static void assert_amcc_cache_disabled() {
#if defined(KERNEL_INTEGRITY_KTRR)
	assert((rMCCGEN & 1) == 0); /* assert M$ disabled or LLC clean will be unreliable */
#else
#error KERNEL_INTEGRITY config error
#endif
}

/*
 * void rorgn_lockdown(void)
 *
 * Lock the MMU and AMCC RORegion within lower and upper boundaries if not already locked
 *
 * [ ] - ensure this is being called ASAP on secondary CPUs: KTRR programming and lockdown handled in
 *       start.s:start_cpu() for subsequent wake/resume of all cores
 */
void rorgn_lockdown(void)
{
	vm_offset_t ktrr_begin, ktrr_end;
	unsigned long plt_segsz, last_segsz;

#if DEVELOPMENT || DEBUG
	boolean_t ktrr_disable = FALSE;

	PE_parse_boot_argn("-unsafe_kernel_text", &ktrr_disable, sizeof(ktrr_disable));

	if (ktrr_disable) {
		/*
		 * take early out if boot arg present, since we may not have amcc DT entry present
		 * we can't assert that iboot hasn't programmed the RO region lockdown registers
		 */
		goto out;
	}
#endif /* DEVELOPMENT || DEBUG */

	assert_unlocked();

	/* [x] - Use final method of determining all kernel text range or expect crashes */

	ktrr_begin = (uint64_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &plt_segsz);
	assert(ktrr_begin && gVirtBase && gPhysBase);

	ktrr_begin = kvtophys(ktrr_begin);

	/* __LAST is not part of the MMU KTRR region (it is however part of the AMCC KTRR region) */
	ktrr_end = (uint64_t) getsegdatafromheader(&_mh_execute_header, "__LAST", &last_segsz);
	ktrr_end = (kvtophys(ktrr_end) - 1) & ~PAGE_MASK;

	/* ensure that iboot and xnu agree on the ktrr range */
	assert(rorgn_begin == ktrr_begin && rorgn_end == (ktrr_end + last_segsz));
	/* assert that __LAST segment containing privileged insns is only a single page */
	assert(last_segsz == PAGE_SIZE);

#if DEBUG
	printf("KTRR Begin: %p End: %p, setting lockdown\n", (void *)ktrr_begin, (void *)ktrr_end);
#endif

	/* [x] - ensure all in flight writes are flushed to AMCC before enabling RO Region Lock */

	assert_amcc_cache_disabled();

	CleanPoC_DcacheRegion_Force(phystokv(ktrr_begin),
		(unsigned)((ktrr_end + last_segsz) - ktrr_begin + PAGE_MASK));

	lock_amcc();

	lock_mmu(ktrr_begin, ktrr_end);

#if DEVELOPMENT || DEBUG
out:
#endif

	/* now we can run lockdown handler */
	ml_lockdown_run_handler();
}

#endif /* defined(KERNEL_INTEGRITY_KTRR)*/

void
machine_startup(__unused boot_args * args)
{
	int boot_arg;


	PE_parse_boot_argn("assert", &mach_assert, sizeof (mach_assert));

	if (PE_parse_boot_argn("preempt", &boot_arg, sizeof (boot_arg))) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_argn("bg_preempt", &boot_arg, sizeof (boot_arg))) {
		default_bg_preemption_rate = boot_arg;
	}

	machine_conf();

	/*
	 * Kick off the kernel bootstrap.
	 */
	kernel_bootstrap();
	/* NOTREACHED */
}

void machine_lockdown_preflight(void)
{
#if CONFIG_KERNEL_INTEGRITY

#if defined(KERNEL_INTEGRITY_KTRR)
       rorgn_stash_range();
#endif

#endif
}

void machine_lockdown(void)
{
#if CONFIG_KERNEL_INTEGRITY
#if KERNEL_INTEGRITY_WT
	/* Watchtower
	 *
	 * Notify the monitor about the completion of early kernel bootstrap.
	 * From this point forward it will enforce the integrity of kernel text,
	 * rodata and page tables.
	 */

#ifdef MONITOR
	monitor_call(MONITOR_LOCKDOWN, 0, 0, 0);
#endif
#endif /* KERNEL_INTEGRITY_WT */


#if defined(KERNEL_INTEGRITY_KTRR)
        /* KTRR
         *
         * Lock physical KTRR region. KTRR region is read-only. Memory outside
         * the region is not executable at EL1.
         */

         rorgn_lockdown();
#endif /* defined(KERNEL_INTEGRITY_KTRR)*/


#endif /* CONFIG_KERNEL_INTEGRITY */
}

char           *
machine_boot_info(
		  __unused char *buf,
		  __unused vm_size_t size)
{
	return (PE_boot_args());
}

void
machine_conf(void)
{
	/*
	 * This is known to be inaccurate. mem_size should always be capped at 2 GB
	 */
	machine_info.memory_size = (uint32_t)mem_size;
}

void
machine_init(void)
{
	debug_log_init();
	clock_config();
	is_clock_configured = TRUE;
	if (debug_enabled)
		pmap_map_globals();
}

void
slave_machine_init(__unused void *param)
{
	cpu_machine_init();	/* Initialize the processor */
	clock_init();		/* Init the clock */
}

/*
 *	Routine:        machine_processor_shutdown
 *	Function:
 */
thread_t
machine_processor_shutdown(
			   __unused thread_t thread,
			   void (*doshutdown) (processor_t),
			   processor_t processor)
{
	return (Shutdown_context(doshutdown, processor));
}

/*
 *	Routine:        ml_init_max_cpus
 *	Function:
 */
void
ml_init_max_cpus(unsigned int max_cpus)
{
	boolean_t       current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
	if (max_cpus_initialized != MAX_CPUS_SET) {
		machine_info.max_cpus = max_cpus;
		machine_info.physical_cpu_max = max_cpus;
		machine_info.logical_cpu_max = max_cpus;
		if (max_cpus_initialized == MAX_CPUS_WAIT)
			thread_wakeup((event_t) & max_cpus_initialized);
		max_cpus_initialized = MAX_CPUS_SET;
	}
	(void) ml_set_interrupts_enabled(current_state);
}

/*
 *	Routine:        ml_get_max_cpus
 *	Function:
 */
unsigned int
ml_get_max_cpus(void)
{
	boolean_t       current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
	if (max_cpus_initialized != MAX_CPUS_SET) {
		max_cpus_initialized = MAX_CPUS_WAIT;
		assert_wait((event_t) & max_cpus_initialized, THREAD_UNINT);
		(void) thread_block(THREAD_CONTINUE_NULL);
	}
	(void) ml_set_interrupts_enabled(current_state);
	return (machine_info.max_cpus);
}

/*
 *      Routine:        ml_init_lock_timeout
 *      Function:
 */
void
ml_init_lock_timeout(void)
{
	uint64_t        abstime;
	uint64_t        mtxspin;
	uint64_t        default_timeout_ns = NSEC_PER_SEC>>2;
	uint32_t        slto;

	if (PE_parse_boot_argn("slto_us", &slto, sizeof (slto)))
		default_timeout_ns = slto * NSEC_PER_USEC;

	nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
	LockTimeOutUsec = (uint32_t)(abstime / NSEC_PER_USEC);
	LockTimeOut = (uint32_t)abstime;

	if (PE_parse_boot_argn("mtxspin", &mtxspin, sizeof (mtxspin))) {
		if (mtxspin > USEC_PER_SEC>>4)
			mtxspin =  USEC_PER_SEC>>4;
			nanoseconds_to_absolutetime(mtxspin*NSEC_PER_USEC, &abstime);
	} else {
		nanoseconds_to_absolutetime(10*NSEC_PER_USEC, &abstime);
	}
	MutexSpin = abstime;
}

/*
 * This is called from the machine-independent routine cpu_up()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_up(void)
{
	hw_atomic_add(&machine_info.physical_cpu, 1);
	hw_atomic_add(&machine_info.logical_cpu, 1);
}

/*
 * This is called from the machine-independent routine cpu_down()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_down(void)
{
	cpu_data_t	*cpu_data_ptr;

	hw_atomic_sub(&machine_info.physical_cpu, 1);
	hw_atomic_sub(&machine_info.logical_cpu, 1);

	/*
	 * If we want to deal with outstanding IPIs, we need to
	 * do relatively early in the processor_doshutdown path,
	 * as we pend decrementer interrupts using the IPI
	 * mechanism if we cannot immediately service them (if
	 * IRQ is masked).  Do so now.
	 *
	 * We aren't on the interrupt stack here; would it make
	 * more sense to disable signaling and then enable
	 * interrupts?  It might be a bit cleaner.
	 */
	cpu_data_ptr = getCpuDatap();
	cpu_data_ptr->cpu_running = FALSE;
	cpu_signal_handler_internal(TRUE);
}

/*
 *	Routine:        ml_cpu_get_info
 *	Function:
 */
void
ml_cpu_get_info(ml_cpu_info_t * ml_cpu_info)
{
	cache_info_t   *cpuid_cache_info;

	cpuid_cache_info = cache_info();
	ml_cpu_info->vector_unit = 0;
	ml_cpu_info->cache_line_size = cpuid_cache_info->c_linesz;
	ml_cpu_info->l1_icache_size = cpuid_cache_info->c_isize;
	ml_cpu_info->l1_dcache_size = cpuid_cache_info->c_dsize;

#if (__ARM_ARCH__ >= 7)
	ml_cpu_info->l2_settings = 1;
	ml_cpu_info->l2_cache_size = cpuid_cache_info->c_l2size;
#else
	ml_cpu_info->l2_settings = 0;
	ml_cpu_info->l2_cache_size = 0xFFFFFFFF;
#endif
	ml_cpu_info->l3_settings = 0;
	ml_cpu_info->l3_cache_size = 0xFFFFFFFF;
}

unsigned int
ml_get_machine_mem(void)
{
	return (machine_info.memory_size);
}

__attribute__((noreturn))
void
halt_all_cpus(boolean_t reboot)
{
	if (reboot) {
		printf("MACH Reboot\n");
		PEHaltRestart(kPERestartCPU);
	} else {
		printf("CPU halted\n");
		PEHaltRestart(kPEHaltCPU);
	}
	while (1);
}

__attribute__((noreturn))
void
halt_cpu(void)
{
	halt_all_cpus(FALSE);
}

/*
 *	Routine:        machine_signal_idle
 *	Function:
 */
void
machine_signal_idle(
		    processor_t processor)
{
	cpu_signal(processor_to_cpu_datap(processor), SIGPnop, (void *)NULL, (void *)NULL);
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REMOTE_AST), processor->cpu_id, 0 /* nop */, 0, 0, 0);
}

void
machine_signal_idle_deferred(
			  processor_t processor)
{
	cpu_signal_deferred(processor_to_cpu_datap(processor));
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REMOTE_DEFERRED_AST), processor->cpu_id, 0 /* nop */, 0, 0, 0);
}

void
machine_signal_idle_cancel(
			  processor_t processor)
{
	cpu_signal_cancel(processor_to_cpu_datap(processor));
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REMOTE_CANCEL_AST), processor->cpu_id, 0 /* nop */, 0, 0, 0);
}

/*
 *	Routine:        ml_install_interrupt_handler
 *	Function:	Initialize Interrupt Handler
 */
void 
ml_install_interrupt_handler(
			     void *nub,
			     int source,
			     void *target,
			     IOInterruptHandler handler,
			     void *refCon)
{
	cpu_data_t     *cpu_data_ptr;
	boolean_t       current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
	cpu_data_ptr = getCpuDatap();

	cpu_data_ptr->interrupt_nub = nub;
	cpu_data_ptr->interrupt_source = source;
	cpu_data_ptr->interrupt_target = target;
	cpu_data_ptr->interrupt_handler = handler;
	cpu_data_ptr->interrupt_refCon = refCon;

	cpu_data_ptr->interrupts_enabled = TRUE;
	(void) ml_set_interrupts_enabled(current_state);

	initialize_screen(NULL, kPEAcquireScreen);
}

/*
 *	Routine:        ml_init_interrupt
 *	Function:	Initialize Interrupts
 */
void
ml_init_interrupt(void)
{
}

/*
 *	Routine:        ml_init_timebase
 *	Function:	register and setup Timebase, Decremeter services
 */
void ml_init_timebase(
	void		*args,
	tbd_ops_t	tbd_funcs,
	vm_offset_t     int_address,
	vm_offset_t     int_value __unused)
{
	cpu_data_t     *cpu_data_ptr;

	cpu_data_ptr = (cpu_data_t *)args;

	if ((cpu_data_ptr == &BootCpuData)
	    && (rtclock_timebase_func.tbd_fiq_handler == (void *)NULL)) {
		rtclock_timebase_func = *tbd_funcs;
		rtclock_timebase_addr = int_address;
	}
}

void
ml_parse_cpu_topology(void)
{
	DTEntry entry, child __unused;
	OpaqueDTEntryIterator iter;
	uint32_t cpu_boot_arg;
	int err;

	cpu_boot_arg = MAX_CPUS;

	PE_parse_boot_argn("cpus", &cpu_boot_arg, sizeof(cpu_boot_arg));

	err = DTLookupEntry(NULL, "/cpus", &entry);
	assert(err == kSuccess);

	err = DTInitEntryIterator(entry, &iter);
	assert(err == kSuccess);

	while (kSuccess == DTIterateEntries(&iter, &child)) {
		unsigned int propSize;
		void *prop = NULL;
		int cpu_id = avail_cpus++;

		if (kSuccess == DTGetProperty(child, "cpu-id", &prop, &propSize))
			cpu_id = *((int32_t*)prop);

		assert(cpu_id < MAX_CPUS);
		assert(cpu_phys_ids[cpu_id] == (uint32_t)-1);

		if (boot_cpu == -1) {
			if (kSuccess != DTGetProperty(child, "state", &prop, &propSize))
				panic("unable to retrieve state for cpu %d", cpu_id);

			if (strncmp((char*)prop, "running", propSize) == 0) {
				boot_cpu = cpu_id;
			}
		}
		if (kSuccess != DTGetProperty(child, "reg", &prop, &propSize))
			panic("unable to retrieve physical ID for cpu %d", cpu_id);

		cpu_phys_ids[cpu_id] = *((uint32_t*)prop);

		if ((cpu_id > max_cpu_number) && ((cpu_id == boot_cpu) || (avail_cpus <= cpu_boot_arg)))
			max_cpu_number = cpu_id;
	}

	if (avail_cpus > cpu_boot_arg)
		avail_cpus = cpu_boot_arg;

	if (avail_cpus == 0)
		panic("No cpus found!");

	if (boot_cpu == -1)
		panic("unable to determine boot cpu!");
}

unsigned int
ml_get_cpu_count(void)
{
	return avail_cpus;
}

int
ml_get_boot_cpu_number(void)
{
	return boot_cpu;
}

cluster_type_t
ml_get_boot_cluster(void)
{
	return boot_cluster;
}

int
ml_get_cpu_number(uint32_t phys_id)
{
	for (int log_id = 0; log_id <= ml_get_max_cpu_number(); ++log_id) {
		if (cpu_phys_ids[log_id] == phys_id)
			return log_id;
	}
	return -1;
}

int
ml_get_max_cpu_number(void)
{
	return max_cpu_number;
}


void ml_lockdown_init() {
    lockdown_handler_grp = lck_grp_alloc_init("lockdown_handler", NULL);
    assert(lockdown_handler_grp != NULL);

    lck_mtx_init(&lockdown_handler_lck, lockdown_handler_grp, NULL);
}

kern_return_t
ml_lockdown_handler_register(lockdown_handler_t f, void *this)
{
    if (lockdown_handler || !f) {
        return KERN_FAILURE;
    }

    lck_mtx_lock(&lockdown_handler_lck);
    lockdown_handler = f;
    lockdown_this = this;

#if !(defined(KERNEL_INTEGRITY_KTRR))
    lockdown_done=1;
    lockdown_handler(this);
#else
    if (lockdown_done) {
        lockdown_handler(this);
    }
#endif
    lck_mtx_unlock(&lockdown_handler_lck);

    return KERN_SUCCESS;
}

void ml_lockdown_run_handler() {
    lck_mtx_lock(&lockdown_handler_lck);
    assert(!lockdown_done);

    lockdown_done = 1;
    if (lockdown_handler) {
        lockdown_handler(lockdown_this);
    }
    lck_mtx_unlock(&lockdown_handler_lck);
}

kern_return_t
ml_processor_register(
                      ml_processor_info_t * in_processor_info,
                      processor_t * processor_out,
                      ipi_handler_t * ipi_handler)
{
	cpu_data_t *this_cpu_datap;
	processor_set_t pset;
	boolean_t  is_boot_cpu;
	static unsigned int reg_cpu_count = 0;

	if (in_processor_info->log_id > (uint32_t)ml_get_max_cpu_number())
		return KERN_FAILURE;

	if ((unsigned int)OSIncrementAtomic((SInt32*)&reg_cpu_count) >= avail_cpus)
		return KERN_FAILURE;

	if (in_processor_info->log_id != (uint32_t)ml_get_boot_cpu_number()) {
		is_boot_cpu = FALSE;
		this_cpu_datap = cpu_data_alloc(FALSE);
		cpu_data_init(this_cpu_datap);
	} else {
		this_cpu_datap = &BootCpuData;
		is_boot_cpu = TRUE;
	}

	assert(in_processor_info->log_id < MAX_CPUS);

	this_cpu_datap->cpu_id = in_processor_info->cpu_id;

	this_cpu_datap->cpu_chud = chudxnu_cpu_alloc(is_boot_cpu);
	if (this_cpu_datap->cpu_chud == (void *)NULL)
		goto processor_register_error;
	this_cpu_datap->cpu_console_buf = console_cpu_alloc(is_boot_cpu);
	if (this_cpu_datap->cpu_console_buf == (void *)(NULL))
		goto processor_register_error;

	if (!is_boot_cpu) {
		this_cpu_datap->cpu_number = in_processor_info->log_id;

		if (cpu_data_register(this_cpu_datap) != KERN_SUCCESS)
			goto processor_register_error;
	}

	this_cpu_datap->cpu_idle_notify = (void *) in_processor_info->processor_idle;
	this_cpu_datap->cpu_cache_dispatch = in_processor_info->platform_cache_dispatch;
	nanoseconds_to_absolutetime((uint64_t) in_processor_info->powergate_latency, &this_cpu_datap->cpu_idle_latency);
	this_cpu_datap->cpu_reset_assist = kvtophys(in_processor_info->powergate_stub_addr);

	this_cpu_datap->idle_timer_notify = (void *) in_processor_info->idle_timer;
	this_cpu_datap->idle_timer_refcon = in_processor_info->idle_timer_refcon;

	this_cpu_datap->platform_error_handler = (void *) in_processor_info->platform_error_handler;
	this_cpu_datap->cpu_regmap_paddr = in_processor_info->regmap_paddr;
	this_cpu_datap->cpu_phys_id = in_processor_info->phys_id;
	this_cpu_datap->cpu_l2_access_penalty = in_processor_info->l2_access_penalty;

	this_cpu_datap->cpu_cluster_type = in_processor_info->cluster_type;
	this_cpu_datap->cpu_cluster_id = in_processor_info->cluster_id;
	this_cpu_datap->cpu_l2_id = in_processor_info->l2_cache_id;
	this_cpu_datap->cpu_l2_size = in_processor_info->l2_cache_size;
	this_cpu_datap->cpu_l3_id = in_processor_info->l3_cache_id;
	this_cpu_datap->cpu_l3_size = in_processor_info->l3_cache_size;

	this_cpu_datap->cluster_master = is_boot_cpu;

	pset = pset_find(in_processor_info->cluster_id, processor_pset(master_processor));
	assert(pset != NULL);
	kprintf("%s>cpu_id %p cluster_id %d cpu_number %d is type %d\n", __FUNCTION__, in_processor_info->cpu_id, in_processor_info->cluster_id, this_cpu_datap->cpu_number, in_processor_info->cluster_type);

	if (!is_boot_cpu) {
		processor_init((struct processor *)this_cpu_datap->cpu_processor,
		               this_cpu_datap->cpu_number, pset);

		if (this_cpu_datap->cpu_l2_access_penalty) {
			/*
			 * Cores that have a non-zero L2 access penalty compared
			 * to the boot processor should be de-prioritized by the
			 * scheduler, so that threads use the cores with better L2
			 * preferentially.
			 */
			processor_set_primary(this_cpu_datap->cpu_processor,
			                      master_processor);
		}
	}

	*processor_out = this_cpu_datap->cpu_processor;
	*ipi_handler = cpu_signal_handler;
	if (in_processor_info->idle_tickle != (idle_tickle_t *) NULL)
		*in_processor_info->idle_tickle = (idle_tickle_t) cpu_idle_tickle;

#if KPC
	if (kpc_register_cpu(this_cpu_datap) != TRUE)
		goto processor_register_error;
#endif

	if (!is_boot_cpu) {
		prng_cpu_init(this_cpu_datap->cpu_number);
		// now let next CPU register itself
		OSIncrementAtomic((SInt32*)&real_ncpus);
	}

	return KERN_SUCCESS;

processor_register_error:
#if KPC
	kpc_unregister_cpu(this_cpu_datap);
#endif
	if (this_cpu_datap->cpu_chud != (void *)NULL)
		chudxnu_cpu_free(this_cpu_datap->cpu_chud);
	if (!is_boot_cpu)
		cpu_data_free(this_cpu_datap);

	return KERN_FAILURE;
}

void
ml_init_arm_debug_interface(
			    void * in_cpu_datap,
			    vm_offset_t virt_address)
{
	((cpu_data_t *)in_cpu_datap)->cpu_debug_interface_map = virt_address;
	do_debugid();
}

/*
 *	Routine:        init_ast_check
 *	Function:
 */
void
init_ast_check(
	       __unused processor_t processor)
{
}

/*
 *	Routine:        cause_ast_check
 *	Function:
 */
void
cause_ast_check(
		 processor_t processor)
{
	if (current_processor() != processor) {
		cpu_signal(processor_to_cpu_datap(processor), SIGPast, (void *)NULL, (void *)NULL);
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REMOTE_AST), processor->cpu_id, 1 /* ast */, 0, 0, 0);
	}
}


/*
 *	Routine:        ml_at_interrupt_context
 *	Function:	Check if running at interrupt context
 */
boolean_t
ml_at_interrupt_context(void)
{
	unsigned int	local;
	vm_offset_t     intstack_top_ptr;

	intstack_top_ptr = getCpuDatap()->intstack_top;
	return (((vm_offset_t)(&local) < intstack_top_ptr) && ((vm_offset_t)(&local) > (intstack_top_ptr - INTSTACK_SIZE)));
}
extern uint32_t cpu_idle_count;

void ml_get_power_state(boolean_t *icp, boolean_t *pidlep) {
	*icp = ml_at_interrupt_context();
	*pidlep = (cpu_idle_count == real_ncpus);
}

/*
 *	Routine:        ml_cause_interrupt
 *	Function:	Generate a fake interrupt
 */
void
ml_cause_interrupt(void)
{
	return;			/* BS_XXX */
}

/* Map memory map IO space */
vm_offset_t
ml_io_map(
	  vm_offset_t phys_addr,
	  vm_size_t size)
{
	return (io_map(phys_addr, size, VM_WIMG_IO));
}

vm_offset_t
ml_io_map_wcomb(
	  vm_offset_t phys_addr,
	  vm_size_t size)
{
	return (io_map(phys_addr, size, VM_WIMG_WCOMB));
}

/* boot memory allocation */
vm_offset_t
ml_static_malloc(
		 __unused vm_size_t size)
{
	return ((vm_offset_t) NULL);
}

vm_map_address_t
ml_map_high_window(
	vm_offset_t	phys_addr,
	vm_size_t	len)
{
	return pmap_map_high_window_bd(phys_addr, len, VM_PROT_READ | VM_PROT_WRITE);
}

vm_offset_t
ml_static_ptovirt(
		  vm_offset_t paddr)
{
	return phystokv(paddr);
}

vm_offset_t
ml_static_vtop(
		  vm_offset_t vaddr)
{
	if (((vm_address_t)(vaddr) - gVirtBase) >= gPhysSize)
		panic("ml_static_ptovirt(): illegal vaddr: %p\n", (void*)vaddr);
	return ((vm_address_t)(vaddr) - gVirtBase + gPhysBase);
}

kern_return_t
ml_static_protect(
	vm_offset_t vaddr, /* kernel virtual address */
	vm_size_t size,
	vm_prot_t new_prot)
{
	pt_entry_t    arm_prot = 0;
	pt_entry_t    arm_block_prot = 0;
	vm_offset_t   vaddr_cur;
	ppnum_t	      ppn;
	kern_return_t result = KERN_SUCCESS;

	if (vaddr < VM_MIN_KERNEL_ADDRESS) {
		panic("ml_static_protect(): %p < %p", (void *) vaddr, (void *) VM_MIN_KERNEL_ADDRESS);
		return KERN_FAILURE;
	}

	assert((vaddr & (PAGE_SIZE - 1)) == 0); /* must be page aligned */

	if ((new_prot & VM_PROT_WRITE) && (new_prot & VM_PROT_EXECUTE)) {
		panic("ml_static_protect(): WX request on %p", (void *) vaddr);
	}

	/* Set up the protection bits, and block bits so we can validate block mappings. */
	if (new_prot & VM_PROT_WRITE) {
		arm_prot |= ARM_PTE_AP(AP_RWNA);
		arm_block_prot |= ARM_TTE_BLOCK_AP(AP_RWNA);
	} else {
		arm_prot |= ARM_PTE_AP(AP_RONA);
		arm_block_prot |= ARM_TTE_BLOCK_AP(AP_RONA);
	}

	arm_prot |= ARM_PTE_NX;
	arm_block_prot |= ARM_TTE_BLOCK_NX;

	if (!(new_prot & VM_PROT_EXECUTE)) {
		arm_prot |= ARM_PTE_PNX;
		arm_block_prot |= ARM_TTE_BLOCK_PNX;
	}

	for (vaddr_cur = vaddr;
	     vaddr_cur < trunc_page_64(vaddr + size);
	     vaddr_cur += PAGE_SIZE) {
		ppn = pmap_find_phys(kernel_pmap, vaddr_cur);
		if (ppn != (vm_offset_t) NULL) {
#if __ARM64_TWO_LEVEL_PMAP__
			tt_entry_t	*tte2;
#else
			tt_entry_t	*tte1, *tte2;
#endif
			pt_entry_t	*pte_p;
			pt_entry_t	ptmp;


#if __ARM64_TWO_LEVEL_PMAP__
			tte2 = &kernel_pmap->tte[(((vaddr_cur) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#else
			tte1 = &kernel_pmap->tte[(((vaddr_cur) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)];
			tte2 = &((tt_entry_t*) phystokv((*tte1) & ARM_TTE_TABLE_MASK))[(((vaddr_cur) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)];
#endif

			if (((*tte2) & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE) {
				if ((((*tte2) & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK) &&
				    ((*tte2 & (ARM_TTE_BLOCK_NXMASK | ARM_TTE_BLOCK_PNXMASK | ARM_TTE_BLOCK_APMASK)) == arm_block_prot)) {
					/*
					 * We can support ml_static_protect on a block mapping if the mapping already has
					 * the desired protections.  We still want to run checks on a per-page basis.
					 */
					continue;
				}

				result = KERN_FAILURE;
				break;
			}

			pte_p = (pt_entry_t *)&((tt_entry_t*)(phystokv((*tte2) & ARM_TTE_TABLE_MASK)))[(((vaddr_cur) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT)];
			ptmp = *pte_p;

			if ((ptmp & ARM_PTE_HINT_MASK) && ((ptmp & (ARM_PTE_APMASK | ARM_PTE_PNXMASK | ARM_PTE_NXMASK)) != arm_prot)) {
				/*
				 * The contiguous hint is similar to a block mapping for ml_static_protect; if the existing
				 * protections do not match the desired protections, then we will fail (as we cannot update
				 * this mapping without updating other mappings as well).
				 */
				result = KERN_FAILURE;
				break;
			}

			__unreachable_ok_push
			if (TEST_PAGE_RATIO_4) {
				{
					unsigned int	i;
					pt_entry_t	*ptep_iter;

					ptep_iter = pte_p;
					for (i=0; i<4; i++, ptep_iter++) {
						/* Note that there is a hole in the HINT sanity checking here. */
						ptmp = *ptep_iter;

						/* We only need to update the page tables if the protections do not match. */
						if ((ptmp & (ARM_PTE_APMASK | ARM_PTE_PNXMASK | ARM_PTE_NXMASK)) != arm_prot) {
							ptmp = (ptmp & ~(ARM_PTE_APMASK | ARM_PTE_PNXMASK | ARM_PTE_NXMASK)) | arm_prot;
							*ptep_iter = ptmp;
						}
					}
				}
#ifndef  __ARM_L1_PTW__
				FlushPoC_DcacheRegion( trunc_page_32(pte_p), 4*sizeof(*pte_p));
#endif
			} else {
				ptmp = *pte_p;

				/* We only need to update the page tables if the protections do not match. */
				if ((ptmp & (ARM_PTE_APMASK | ARM_PTE_PNXMASK | ARM_PTE_NXMASK)) != arm_prot) {
					ptmp = (ptmp & ~(ARM_PTE_APMASK | ARM_PTE_PNXMASK | ARM_PTE_NXMASK)) | arm_prot;
					*pte_p = ptmp;
				}

#ifndef  __ARM_L1_PTW__
				FlushPoC_DcacheRegion( trunc_page_32(pte_p), sizeof(*pte_p));
#endif
			}
			__unreachable_ok_pop
		}
	}

	if (vaddr_cur > vaddr) {
		assert(((vaddr_cur - vaddr) & 0xFFFFFFFF00000000ULL) == 0);
		flush_mmu_tlb_region(vaddr, (uint32_t)(vaddr_cur - vaddr));
	}


	return result;
}

/*
 *	Routine:        ml_static_mfree
 *	Function:
 */
void
ml_static_mfree(
		vm_offset_t vaddr,
		vm_size_t size)
{
	vm_offset_t     vaddr_cur;
	ppnum_t         ppn;
	uint32_t freed_pages = 0;

	/* It is acceptable (if bad) to fail to free. */
	if (vaddr < VM_MIN_KERNEL_ADDRESS)
		return;

	assert((vaddr & (PAGE_SIZE - 1)) == 0);	/* must be page aligned */

	for (vaddr_cur = vaddr;
	     vaddr_cur < trunc_page_64(vaddr + size);
	     vaddr_cur += PAGE_SIZE) {

		ppn = pmap_find_phys(kernel_pmap, vaddr_cur);
		if (ppn != (vm_offset_t) NULL) {
			/*
			 * It is not acceptable to fail to update the protections on a page
			 * we will release to the VM.  We need to either panic or continue.
			 * For now, we'll panic (to help flag if there is memory we can
			 * reclaim).
			 */
			if (ml_static_protect(vaddr_cur, PAGE_SIZE, VM_PROT_WRITE | VM_PROT_READ) != KERN_SUCCESS) {
				panic("Failed ml_static_mfree on %p", (void *) vaddr_cur);
			}

#if 0
			/*
			 * Must NOT tear down the "V==P" mapping for vaddr_cur as the zone alias scheme
			 * relies on the persistence of these mappings for all time.
			 */
			// pmap_remove(kernel_pmap, (addr64_t) vaddr_cur, (addr64_t) (vaddr_cur + PAGE_SIZE));
#endif

			vm_page_create(ppn, (ppn + 1));
			freed_pages++;
		}
	}
	vm_page_lockspin_queues();
	vm_page_wire_count -= freed_pages;
	vm_page_wire_count_initial -= freed_pages;
	vm_page_unlock_queues();
#if	DEBUG
	kprintf("ml_static_mfree: Released 0x%x pages at VA %p, size:0x%llx, last ppn: 0x%x\n", freed_pages, (void *)vaddr, (uint64_t)size, ppn);
#endif
}


/* virtual to physical on wired pages */
vm_offset_t
ml_vtophys(vm_offset_t vaddr)
{
	return kvtophys(vaddr);
}

/*
 * Routine: ml_nofault_copy
 * Function: Perform a physical mode copy if the source and destination have
 * valid translations in the kernel pmap. If translations are present, they are
 * assumed to be wired; e.g., no attempt is made to guarantee that the
 * translations obtained remain valid for the duration of the copy process.
 */
vm_size_t
ml_nofault_copy(vm_offset_t virtsrc, vm_offset_t virtdst, vm_size_t size)
{
	addr64_t        cur_phys_dst, cur_phys_src;
	vm_size_t 	count, nbytes = 0;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc)))
			break;
		if (!(cur_phys_dst = kvtophys(virtdst)))
			break;
		if (!pmap_valid_address(trunc_page_64(cur_phys_dst)) ||
		    !pmap_valid_address(trunc_page_64(cur_phys_src)))
			break;
		count = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		if (count > (PAGE_SIZE - (cur_phys_dst & PAGE_MASK)))
			count = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (count > size)
			count = size;

		bcopy_phys(cur_phys_src, cur_phys_dst, count);

		nbytes += count;
		virtsrc += count;
		virtdst += count;
		size -= count;
	}

	return nbytes;
}

/*
 *	Routine:        ml_validate_nofault
 *	Function: Validate that ths address range has a valid translations
 *			in the kernel pmap.  If translations are present, they are
 *			assumed to be wired; i.e. no attempt is made to guarantee
 *			that the translation persist after the check.
 *  Returns: TRUE if the range is mapped and will not cause a fault,
 *			FALSE otherwise.
 */

boolean_t ml_validate_nofault(
	vm_offset_t virtsrc, vm_size_t size)
{
	addr64_t cur_phys_src;
	uint32_t count;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc)))
			return FALSE;
		if (!pmap_valid_address(trunc_page_64(cur_phys_src)))
			return FALSE;
		count = (uint32_t)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		if (count > size)
			count = (uint32_t)size;

		virtsrc += count;
		size -= count;
	}

	return TRUE;
}

void
ml_get_bouncepool_info(vm_offset_t * phys_addr, vm_size_t * size)
{
	*phys_addr = 0;
	*size = 0;
}

void
active_rt_threads(__unused boolean_t active)
{
}

static void cpu_qos_cb_default(__unused int urgency, __unused uint64_t qos_param1, __unused uint64_t qos_param2) {
	return;
}

cpu_qos_update_t cpu_qos_update = cpu_qos_cb_default;

void cpu_qos_update_register(cpu_qos_update_t cpu_qos_cb) {
	if (cpu_qos_cb != NULL) {
		cpu_qos_update = cpu_qos_cb;
	} else {
		cpu_qos_update = cpu_qos_cb_default;
	}
}

void
thread_tell_urgency(int urgency, uint64_t rt_period, uint64_t rt_deadline, uint64_t sched_latency __unused, __unused thread_t nthread)
{
	SCHED_DEBUG_PLATFORM_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_URGENCY) | DBG_FUNC_START, urgency, rt_period, rt_deadline, sched_latency, 0);

	cpu_qos_update(urgency, rt_period, rt_deadline);

	SCHED_DEBUG_PLATFORM_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_URGENCY) | DBG_FUNC_END, urgency, rt_period, rt_deadline, 0, 0);
}

void
machine_run_count(__unused uint32_t count)
{
}

processor_t
machine_choose_processor(__unused processor_set_t pset, processor_t processor)
{
	return (processor);
}

vm_offset_t
ml_stack_remaining(void)
{
	uintptr_t local = (uintptr_t) &local;

	if (ml_at_interrupt_context()) {
	    return (local - (getCpuDatap()->intstack_top - INTSTACK_SIZE));
	} else {
	    return (local - current_thread()->kernel_stack);
	}
}

#if KASAN
vm_offset_t ml_stack_base(void);
vm_size_t ml_stack_size(void);

vm_offset_t
ml_stack_base(void)
{
	if (ml_at_interrupt_context()) {
	    return getCpuDatap()->intstack_top - INTSTACK_SIZE;
	} else {
	    return current_thread()->kernel_stack;
	}
}
vm_size_t
ml_stack_size(void)
{
	if (ml_at_interrupt_context()) {
	    return INTSTACK_SIZE;
	} else {
	    return kernel_stack_size;
	}
}
#endif

boolean_t machine_timeout_suspended(void) {
	return FALSE;
}

kern_return_t
ml_interrupt_prewarm(__unused uint64_t deadline)
{
	return KERN_FAILURE;
}

/*
 * Assumes fiq, irq disabled.
 */
void
ml_set_decrementer(uint32_t dec_value)
{
	cpu_data_t 	*cdp = getCpuDatap();

	assert(ml_get_interrupts_enabled() == FALSE);
	cdp->cpu_decrementer = dec_value;

	if (cdp->cpu_set_decrementer_func)  {
		((void (*)(uint32_t))cdp->cpu_set_decrementer_func)(dec_value);
	} else {
		__asm__ volatile("msr CNTP_TVAL_EL0, %0" : : "r"((uint64_t)dec_value));
	}
}

uint64_t ml_get_hwclock()
{
	uint64_t timebase;

	// ISB required by ARMV7C.b section B8.1.2 & ARMv8 section D6.1.2
	// "Reads of CNTPCT[_EL0] can occur speculatively and out of order relative
	// to other instructions executed on the same processor."
	__asm__ volatile("isb\n"
			 "mrs %0, CNTPCT_EL0"
			 : "=r"(timebase));

	return timebase;
}

uint64_t
ml_get_timebase()
{
	return (ml_get_hwclock() + getCpuDatap()->cpu_base_timebase);
}

uint32_t
ml_get_decrementer()
{
	cpu_data_t *cdp = getCpuDatap();
	uint32_t dec;

	assert(ml_get_interrupts_enabled() == FALSE);

	if (cdp->cpu_get_decrementer_func) {
		dec = ((uint32_t (*)(void))cdp->cpu_get_decrementer_func)();
	} else {
		uint64_t wide_val;

		__asm__ volatile("mrs %0, CNTP_TVAL_EL0" : "=r"(wide_val));
		dec = (uint32_t)wide_val;
		assert(wide_val == (uint64_t)dec);
	}

	return dec;
}

boolean_t
ml_get_timer_pending()
{
	uint64_t cntp_ctl;

	__asm__ volatile("mrs %0, CNTP_CTL_EL0" : "=r"(cntp_ctl));
	return ((cntp_ctl & CNTP_CTL_EL0_ISTATUS) != 0) ? TRUE : FALSE;
}

boolean_t
ml_wants_panic_trap_to_debugger(void)
{
	boolean_t result = FALSE;
	return result;
}

static void
cache_trap_error(thread_t thread, vm_map_address_t fault_addr)
{
	mach_exception_data_type_t exc_data[2];
	arm_saved_state_t *regs = get_user_regs(thread);

	set_saved_state_far(regs, fault_addr);

	exc_data[0] = KERN_INVALID_ADDRESS;
	exc_data[1] = fault_addr;

	exception_triage(EXC_BAD_ACCESS, exc_data, 2);
}

static void
cache_trap_recover()
{
	vm_map_address_t fault_addr;

	__asm__ volatile("mrs %0, FAR_EL1" : "=r"(fault_addr));

	cache_trap_error(current_thread(), fault_addr);
}

static void
dcache_flush_trap(vm_map_address_t start, vm_map_size_t size)
{
	vm_map_address_t end = start + size;
	thread_t thread = current_thread();
	vm_offset_t old_recover = thread->recover;

	/* Check bounds */
	if (task_has_64BitAddr(current_task())) {
		if (end > MACH_VM_MAX_ADDRESS) {
			cache_trap_error(thread, end & ((1 << ARM64_CLINE_SHIFT) - 1));
		}
	} else {
		if (end > VM_MAX_ADDRESS) {
			cache_trap_error(thread, end & ((1 << ARM64_CLINE_SHIFT) - 1));
		}
	}

	if (start > end) {
		cache_trap_error(thread, start & ((1 << ARM64_CLINE_SHIFT) - 1));
	}

	/* Set recovery function */
	thread->recover = (vm_address_t)cache_trap_recover;

#if defined(APPLE_ARM64_ARCH_FAMILY)
	/*
	 * We're coherent on Apple ARM64 CPUs, so this could be a nop.  However,
	 * if the region given us is bad, it would be good to catch it and
	 * crash, ergo we still do the flush.
	 */
	assert((size & 0xFFFFFFFF00000000ULL) == 0);
	FlushPoC_DcacheRegion(start, (uint32_t)size);
#else
#error "Make sure you don't need to xcall."
#endif

	/* Restore recovery function */
	thread->recover = old_recover;

	/* Return (caller does exception return) */
}

static void
icache_invalidate_trap(vm_map_address_t start, vm_map_size_t size)
{
	vm_map_address_t end = start + size;
	thread_t thread = current_thread();
	vm_offset_t old_recover = thread->recover;

	/* Check bounds */
	if (task_has_64BitAddr(current_task())) {
		if (end > MACH_VM_MAX_ADDRESS) {
			cache_trap_error(thread, end & ((1 << ARM64_CLINE_SHIFT) - 1));
		}
	} else {
		if (end > VM_MAX_ADDRESS) {
			cache_trap_error(thread, end & ((1 << ARM64_CLINE_SHIFT) - 1));
		}
	}

	if (start > end) {
		cache_trap_error(thread, start & ((1 << ARM64_CLINE_SHIFT) - 1));
	}

	/* Set recovery function */
	thread->recover = (vm_address_t)cache_trap_recover;

#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* Clean dcache to unification, except we're coherent on Apple ARM64 CPUs */
#else
#error Make sure not cleaning is right for this platform!
#endif

	/* Invalidate iCache to point of unification */
	assert((size & 0xFFFFFFFF00000000ULL) == 0);
	InvalidatePoU_IcacheRegion(start, (uint32_t)size);

	/* Restore recovery function */
	thread->recover = old_recover;

	/* Return (caller does exception return) */
}

__attribute__((noreturn))
void
platform_syscall(arm_saved_state_t *state)
{
	uint32_t code;

#define platform_syscall_kprintf(x...) /* kprintf("platform_syscall: " x) */

	code = (uint32_t)get_saved_state_reg(state, 3);
	switch (code) {
	case 0:
		/* I-Cache flush */
		platform_syscall_kprintf("icache flush requested.\n");
		icache_invalidate_trap(get_saved_state_reg(state, 0), get_saved_state_reg(state, 1));
		break;
	case 1:
		/* D-Cache flush */
		platform_syscall_kprintf("dcache flush requested.\n");
		dcache_flush_trap(get_saved_state_reg(state, 0), get_saved_state_reg(state, 1));
		break;
	case 2:
		/* set cthread */
		platform_syscall_kprintf("set cthread self.\n");
		thread_set_cthread_self(get_saved_state_reg(state, 0));
		break;
	case 3:
		/* get cthread */
		platform_syscall_kprintf("get cthread self.\n");
		set_saved_state_reg(state, 0, thread_get_cthread_self());
		break;
	default:
		platform_syscall_kprintf("unknown: %d\n", code);
		break;
	}

	thread_exception_return();
}

static void
_enable_timebase_event_stream(uint32_t bit_index)
{
	uint64_t cntkctl; /* One wants to use 32 bits, but "mrs" prefers it this way */

	if (bit_index >= 64) {
		panic("%s: invalid bit index (%u)", __FUNCTION__, bit_index);
	}

	__asm__ volatile ("mrs	%0, CNTKCTL_EL1" : "=r"(cntkctl));

	cntkctl |= (bit_index << CNTKCTL_EL1_EVENTI_SHIFT);
	cntkctl |= CNTKCTL_EL1_EVNTEN;
	cntkctl |= CNTKCTL_EL1_EVENTDIR; /* 1->0; why not? */

	/*
	 * If the SOC supports it (and it isn't broken), enable
	 * EL0 access to the physical timebase register.
	 */
	if (user_timebase_allowed()) {
		cntkctl |= CNTKCTL_EL1_PL0PCTEN;
	}

	__asm__ volatile ("msr	CNTKCTL_EL1, %0" : : "r"(cntkctl));
}

/*
 * Turn timer on, unmask that interrupt.
 */
static void
_enable_virtual_timer(void)
{
	uint64_t cntvctl = CNTP_CTL_EL0_ENABLE; /* One wants to use 32 bits, but "mrs" prefers it this way */

	__asm__ volatile ("msr CNTP_CTL_EL0, %0" : : "r"(cntvctl));
}

void
fiq_context_init(boolean_t enable_fiq __unused)
{
#if defined(APPLE_ARM64_ARCH_FAMILY)
	/* Could fill in our own ops here, if we needed them */
	uint64_t 	ticks_per_sec, ticks_per_event, events_per_sec;
	uint32_t	bit_index;

	ticks_per_sec = gPEClockFrequencyInfo.timebase_frequency_hz;
#if defined(ARM_BOARD_WFE_TIMEOUT_NS)
	events_per_sec = 1000000000 / ARM_BOARD_WFE_TIMEOUT_NS;
#else
	/* Default to 1usec (or as close as we can get) */
	events_per_sec = 1000000;
#endif
	ticks_per_event = ticks_per_sec / events_per_sec;
	bit_index = flsll(ticks_per_event) - 1; /* Highest bit set */

	/* Round up to power of two */
	if ((ticks_per_event & ((1 << bit_index) - 1)) != 0) {
		bit_index++;
	}

	/*
	 * The timer can only trigger on rising or falling edge,
	 * not both; we don't care which we trigger on, but we
	 * do need to adjust which bit we are interested in to
	 * account for this.
	 */
	if (bit_index != 0)
		bit_index--;

	_enable_timebase_event_stream(bit_index);
#else
#error Need a board configuration.
#endif

	/* Interrupts still disabled. */
	assert(ml_get_interrupts_enabled() == FALSE);
	_enable_virtual_timer();
}

/*
 * ARM64_TODO: remove me (just a convenience while we don't have crashreporter)
 */
extern int copyinframe(vm_address_t, char *, boolean_t);
size_t 		_OSUserBacktrace(char *buffer, size_t bufsize);

size_t _OSUserBacktrace(char *buffer, size_t bufsize) 
{
	thread_t thread = current_thread();
	boolean_t is64bit = thread_is_64bit(thread);
	size_t trace_size_bytes = 0, lr_size;
	vm_address_t frame_addr; // Should really by mach_vm_offset_t...

	if (bufsize < 8) {
		return 0;
	}

	if (get_threadtask(thread) == kernel_task) {
		panic("%s: Should never be called from a kernel thread.", __FUNCTION__);
	}

	frame_addr = get_saved_state_fp(thread->machine.upcb);
	if (is64bit) {
		uint64_t frame[2];
		lr_size = sizeof(frame[1]);

		*((uint64_t*)buffer) = get_saved_state_pc(thread->machine.upcb);
		trace_size_bytes = lr_size;

		while (trace_size_bytes + lr_size < bufsize) {
			if (!(frame_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS)) {
				break;
			}

			if (0 != copyinframe(frame_addr, (char*)frame, TRUE)) {
				break;
			}

			*((uint64_t*)(buffer + trace_size_bytes)) = frame[1]; /* lr */
			frame_addr = frame[0];
			trace_size_bytes += lr_size;

			if (frame[0] == 0x0ULL) {
				break;
			}
		}
	} else {
		uint32_t frame[2];
		lr_size = sizeof(frame[1]);

		*((uint32_t*)buffer) = (uint32_t)get_saved_state_pc(thread->machine.upcb);
		trace_size_bytes = lr_size;

		while (trace_size_bytes + lr_size < bufsize) {
			if (!(frame_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS)) {
				break;
			}

			if (0 != copyinframe(frame_addr, (char*)frame, FALSE)) {
				break;
			}

			*((uint32_t*)(buffer + trace_size_bytes)) = frame[1]; /* lr */
			frame_addr = frame[0];
			trace_size_bytes += lr_size;

			if (frame[0] == 0x0ULL) {
				break;
			}
		}
	}

	return trace_size_bytes;
}

boolean_t
ml_delay_should_spin(uint64_t interval)
{
	cpu_data_t     *cdp = getCpuDatap();

	if (cdp->cpu_idle_latency) {
		return (interval < cdp->cpu_idle_latency) ? TRUE : FALSE;
	} else {
		/*
		 * Early boot, latency is unknown. Err on the side of blocking,
		 * which should always be safe, even if slow
		 */
		return FALSE;
	}
}

boolean_t ml_thread_is64bit(thread_t thread) {
	return (thread_is_64bit(thread));
}

void ml_timer_evaluate(void) {
}

boolean_t
ml_timer_forced_evaluation(void) {
	return FALSE;
}

uint64_t
ml_energy_stat(thread_t t) {
	return t->machine.energy_estimate_nj;
}


void
ml_gpu_stat_update(__unused uint64_t gpu_ns_delta) {
#if CONFIG_EMBEDDED
	/*
	 * For now: update the resource coalition stats of the
	 * current thread's coalition
	 */
	task_coalition_update_gpu_stats(current_task(), gpu_ns_delta);
#endif
}

uint64_t
ml_gpu_stat(__unused thread_t t) {
	return 0;
}

#if !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
static void
timer_state_event(boolean_t switch_to_kernel)
{
	thread_t thread = current_thread();
	if (!thread->precise_user_kernel_time) return;

	processor_data_t *pd = &getCpuDatap()->cpu_processor->processor_data;
	uint64_t now = ml_get_timebase();

	timer_stop(pd->current_state, now);
	pd->current_state = (switch_to_kernel) ? &pd->system_state : &pd->user_state;
	timer_start(pd->current_state, now);

	timer_stop(pd->thread_timer, now);
	pd->thread_timer = (switch_to_kernel) ? &thread->system_timer : &thread->user_timer;
	timer_start(pd->thread_timer, now);
}

void
timer_state_event_user_to_kernel(void)
{
	timer_state_event(TRUE);
}

void
timer_state_event_kernel_to_user(void)
{
	timer_state_event(FALSE);
}
#endif /* !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */

/*
 * The following are required for parts of the kernel
 * that cannot resolve these functions as inlines:
 */
extern thread_t current_act(void);
thread_t
current_act(void)
{
	return current_thread_fast();
}

#undef current_thread
extern thread_t current_thread(void);
thread_t
current_thread(void)
{
	return current_thread_fast();
}

typedef struct
{
	ex_cb_t		cb;
	void		*refcon;
}
ex_cb_info_t;

ex_cb_info_t ex_cb_info[EXCB_CLASS_MAX];

/*
 * Callback registration
 * Currently we support only one registered callback per class but
 * it should be possible to support more callbacks
 */
kern_return_t ex_cb_register(
	ex_cb_class_t	cb_class,
	ex_cb_t			cb,
	void			*refcon)
{
	ex_cb_info_t *pInfo = &ex_cb_info[cb_class];

	if ((NULL == cb) || (cb_class >= EXCB_CLASS_MAX))
	{
		return KERN_INVALID_VALUE;
	}

	if (NULL == pInfo->cb)
	{
		pInfo->cb = cb;
		pInfo->refcon = refcon;
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

/*
 * Called internally by platform kernel to invoke the registered callback for class
 */
ex_cb_action_t ex_cb_invoke(
	ex_cb_class_t	cb_class,
	vm_offset_t		far)
{
	ex_cb_info_t *pInfo = &ex_cb_info[cb_class];
	ex_cb_state_t state = {far};

	if (cb_class >= EXCB_CLASS_MAX)
	{
		panic("Invalid exception callback class 0x%x\n", cb_class);
	}

	if (pInfo->cb)
	{
		return pInfo->cb(cb_class, pInfo->refcon, &state);
	}
	return EXCB_ACTION_NONE;
}

