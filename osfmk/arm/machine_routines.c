/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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

#include <arm/proc_reg.h>
#include <arm/machine_cpu.h>
#include <arm/cpu_internal.h>
#include <arm/cpuid.h>
#include <arm/io_map_entries.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/rtclock.h>
#include <arm/caches_internal.h>
#include <console/serial_protos.h>
#include <kern/machine.h>
#include <prng/random.h>
#include <kern/startup.h>
#include <kern/sched.h>
#include <kern/thread.h>
#include <mach/machine.h>
#include <machine/atomic.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <sys/kdebug.h>
#include <kern/coalition.h>
#include <pexpert/device_tree.h>
#include <arm/cpuid_internal.h>
#include <arm/cpu_capabilities.h>

#include <IOKit/IOPlatformExpert.h>

#if KPC
#include <kern/kpc.h>
#endif

static int max_cpus_initialized = 0;
#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

static unsigned int avail_cpus = 0;

uint32_t LockTimeOut;
uint32_t LockTimeOutUsec;
uint64_t TLockTimeOut;
uint64_t MutexSpin;
boolean_t is_clock_configured = FALSE;

#if CONFIG_NONFATAL_ASSERTS
extern int mach_assert;
#endif
extern volatile uint32_t debug_enabled;

void machine_conf(void);

void
machine_startup(__unused boot_args * args)
{
	int boot_arg;

#if CONFIG_NONFATAL_ASSERTS
	PE_parse_boot_argn("assert", &mach_assert, sizeof(mach_assert));
#endif

	if (PE_parse_boot_argn("preempt", &boot_arg, sizeof(boot_arg))) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_argn("bg_preempt", &boot_arg, sizeof(boot_arg))) {
		default_bg_preemption_rate = boot_arg;
	}

	machine_conf();

	/*
	 * Kick off the kernel bootstrap.
	 */
	kernel_bootstrap();
	/* NOTREACHED */
}

char           *
machine_boot_info(
	__unused char *buf,
	__unused vm_size_t size)
{
	return PE_boot_args();
}

void
machine_conf(void)
{
	machine_info.memory_size = mem_size;
}

void
machine_init(void)
{
	debug_log_init();
	clock_config();
	is_clock_configured = TRUE;
	if (debug_enabled) {
		pmap_map_globals();
	}
}

void
slave_machine_init(__unused void *param)
{
	cpu_machine_init();     /* Initialize the processor */
	clock_init();           /* Init the clock */
}

/*
 *	Routine:        machine_processor_shutdown
 *	Function:
 */
thread_t
machine_processor_shutdown(
	__unused thread_t thread,
	void (*doshutdown)(processor_t),
	processor_t processor)
{
	return Shutdown_context(doshutdown, processor);
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
		if (max_cpus_initialized == MAX_CPUS_WAIT) {
			thread_wakeup((event_t) &max_cpus_initialized);
		}
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
		assert_wait((event_t) &max_cpus_initialized, THREAD_UNINT);
		(void) thread_block(THREAD_CONTINUE_NULL);
	}
	(void) ml_set_interrupts_enabled(current_state);
	return machine_info.max_cpus;
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
	uint64_t        default_timeout_ns = NSEC_PER_SEC >> 2;
	uint32_t        slto;

	if (PE_parse_boot_argn("slto_us", &slto, sizeof(slto))) {
		default_timeout_ns = slto * NSEC_PER_USEC;
	}

	nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
	LockTimeOutUsec = (uint32_t)(default_timeout_ns / NSEC_PER_USEC);
	LockTimeOut = (uint32_t)abstime;
	TLockTimeOut = LockTimeOut;

	if (PE_parse_boot_argn("mtxspin", &mtxspin, sizeof(mtxspin))) {
		if (mtxspin > USEC_PER_SEC >> 4) {
			mtxspin =  USEC_PER_SEC >> 4;
		}
		nanoseconds_to_absolutetime(mtxspin * NSEC_PER_USEC, &abstime);
	} else {
		nanoseconds_to_absolutetime(10 * NSEC_PER_USEC, &abstime);
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
	os_atomic_inc(&machine_info.physical_cpu, relaxed);
	os_atomic_inc(&machine_info.logical_cpu, relaxed);
}

/*
 * This is called from the machine-independent routine cpu_down()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_down(void)
{
	cpu_data_t      *cpu_data_ptr;

	os_atomic_dec(&machine_info.physical_cpu, relaxed);
	os_atomic_dec(&machine_info.logical_cpu, relaxed);

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
	return machine_info.memory_size;
}

/* Return max offset */
vm_map_offset_t
ml_get_max_offset(
	boolean_t       is64,
	unsigned int option)
{
	unsigned int    pmap_max_offset_option = 0;

	switch (option) {
	case MACHINE_MAX_OFFSET_DEFAULT:
		pmap_max_offset_option = ARM_PMAP_MAX_OFFSET_DEFAULT;
		break;
	case MACHINE_MAX_OFFSET_MIN:
		pmap_max_offset_option =  ARM_PMAP_MAX_OFFSET_MIN;
		break;
	case MACHINE_MAX_OFFSET_MAX:
		pmap_max_offset_option = ARM_PMAP_MAX_OFFSET_MAX;
		break;
	case MACHINE_MAX_OFFSET_DEVICE:
		pmap_max_offset_option = ARM_PMAP_MAX_OFFSET_DEVICE;
		break;
	default:
		panic("ml_get_max_offset(): Illegal option 0x%x\n", option);
		break;
	}
	return pmap_max_offset(is64, pmap_max_offset_option);
}

boolean_t
ml_wants_panic_trap_to_debugger(void)
{
	return FALSE;
}

void
ml_panic_trap_to_debugger(__unused const char *panic_format_str,
    __unused va_list *panic_args,
    __unused unsigned int reason,
    __unused void *ctx,
    __unused uint64_t panic_options_mask,
    __unused unsigned long panic_caller)
{
	return;
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
	while (1) {
		;
	}
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
void
ml_init_timebase(
	void            *args,
	tbd_ops_t       tbd_funcs,
	vm_offset_t     int_address,
	vm_offset_t     int_value)
{
	cpu_data_t     *cpu_data_ptr;

	cpu_data_ptr = (cpu_data_t *)args;

	if ((cpu_data_ptr == &BootCpuData)
	    && (rtclock_timebase_func.tbd_fiq_handler == (void *)NULL)) {
		rtclock_timebase_func = *tbd_funcs;
		rtclock_timebase_addr = int_address;
		rtclock_timebase_val = int_value;
	}
}

void
fiq_context_bootstrap(boolean_t enable_fiq)
{
	fiq_context_init(enable_fiq);
}

void
ml_parse_cpu_topology(void)
{
	DTEntry entry, child;
	OpaqueDTEntryIterator iter;
	uint32_t cpu_boot_arg;
	int err;

	err = DTLookupEntry(NULL, "/cpus", &entry);
	assert(err == kSuccess);

	err = DTInitEntryIterator(entry, &iter);
	assert(err == kSuccess);

	while (kSuccess == DTIterateEntries(&iter, &child)) {
#if MACH_ASSERT
		unsigned int propSize;
		void *prop = NULL;
		if (avail_cpus == 0) {
			if (kSuccess != DTGetProperty(child, "state", &prop, &propSize)) {
				panic("unable to retrieve state for cpu %u", avail_cpus);
			}

			if (strncmp((char*)prop, "running", propSize) != 0) {
				panic("cpu 0 has not been marked as running!");
			}
		}
		assert(kSuccess == DTGetProperty(child, "reg", &prop, &propSize));
		assert(avail_cpus == *((uint32_t*)prop));
#endif
		++avail_cpus;
	}

	cpu_boot_arg = avail_cpus;
	if (PE_parse_boot_argn("cpus", &cpu_boot_arg, sizeof(cpu_boot_arg)) &&
	    (avail_cpus > cpu_boot_arg)) {
		avail_cpus = cpu_boot_arg;
	}

	if (avail_cpus == 0) {
		panic("No cpus found!");
	}
}

unsigned int
ml_get_cpu_count(void)
{
	return avail_cpus;
}

int
ml_get_boot_cpu_number(void)
{
	return 0;
}

cluster_type_t
ml_get_boot_cluster(void)
{
	return CLUSTER_TYPE_SMP;
}

int
ml_get_cpu_number(uint32_t phys_id)
{
	return (int)phys_id;
}

int
ml_get_max_cpu_number(void)
{
	return avail_cpus - 1;
}

kern_return_t
ml_processor_register(ml_processor_info_t *in_processor_info,
    processor_t * processor_out, ipi_handler_t *ipi_handler_out,
    perfmon_interrupt_handler_func *pmi_handler_out)
{
	cpu_data_t *this_cpu_datap;
	boolean_t  is_boot_cpu;

	if (in_processor_info->phys_id >= MAX_CPUS) {
		/*
		 * The physical CPU ID indicates that we have more CPUs than
		 * this xnu build support.  This probably means we have an
		 * incorrect board configuration.
		 *
		 * TODO: Should this just return a failure instead?  A panic
		 * is simply a convenient way to catch bugs in the pexpert
		 * headers.
		 */
		panic("phys_id %u is too large for MAX_CPUS (%u)", in_processor_info->phys_id, MAX_CPUS);
	}

	/* Fail the registration if the number of CPUs has been limited by boot-arg. */
	if ((in_processor_info->phys_id >= avail_cpus) ||
	    (in_processor_info->log_id > (uint32_t)ml_get_max_cpu_number())) {
		return KERN_FAILURE;
	}

	if (in_processor_info->log_id != (uint32_t)ml_get_boot_cpu_number()) {
		is_boot_cpu = FALSE;
		this_cpu_datap = cpu_data_alloc(FALSE);
		cpu_data_init(this_cpu_datap);
	} else {
		this_cpu_datap = &BootCpuData;
		is_boot_cpu = TRUE;
	}

	this_cpu_datap->cpu_id = in_processor_info->cpu_id;

	this_cpu_datap->cpu_console_buf = console_cpu_alloc(is_boot_cpu);
	if (this_cpu_datap->cpu_console_buf == (void *)(NULL)) {
		goto processor_register_error;
	}

	if (!is_boot_cpu) {
		if (cpu_data_register(this_cpu_datap) != KERN_SUCCESS) {
			goto processor_register_error;
		}
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

	if (!is_boot_cpu) {
		processor_init((struct processor *)this_cpu_datap->cpu_processor,
		    this_cpu_datap->cpu_number, processor_pset(master_processor));

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
	*ipi_handler_out = cpu_signal_handler;
	*pmi_handler_out = NULL;
	if (in_processor_info->idle_tickle != (idle_tickle_t *) NULL) {
		*in_processor_info->idle_tickle = (idle_tickle_t) cpu_idle_tickle;
	}

#if KPC
	if (kpc_register_cpu(this_cpu_datap) != TRUE) {
		goto processor_register_error;
	}
#endif

	if (!is_boot_cpu) {
		random_cpu_init(this_cpu_datap->cpu_number);
	}

	return KERN_SUCCESS;

processor_register_error:
#if KPC
	kpc_unregister_cpu(this_cpu_datap);
#endif
	if (!is_boot_cpu) {
		cpu_data_free(this_cpu_datap);
	}
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

extern uint32_t cpu_idle_count;

void
ml_get_power_state(boolean_t *icp, boolean_t *pidlep)
{
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
	return;                 /* BS_XXX */
}

/* Map memory map IO space */
vm_offset_t
ml_io_map(
	vm_offset_t phys_addr,
	vm_size_t size)
{
	return io_map(phys_addr, size, VM_WIMG_IO);
}

/* Map memory map IO space (with protections specified) */
vm_offset_t
ml_io_map_with_prot(
	vm_offset_t phys_addr,
	vm_size_t size,
	vm_prot_t prot)
{
	return io_map_with_prot(phys_addr, size, VM_WIMG_IO, prot);
}

vm_offset_t
ml_io_map_wcomb(
	vm_offset_t phys_addr,
	vm_size_t size)
{
	return io_map(phys_addr, size, VM_WIMG_WCOMB);
}

/* boot memory allocation */
vm_offset_t
ml_static_malloc(
	__unused vm_size_t size)
{
	return (vm_offset_t) NULL;
}

vm_map_address_t
ml_map_high_window(
	vm_offset_t     phys_addr,
	vm_size_t       len)
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
	assertf(((vm_address_t)(vaddr) - gVirtBase) < gPhysSize, "%s: illegal vaddr: %p", __func__, (void*)vaddr);
	return (vm_address_t)(vaddr) - gVirtBase + gPhysBase;
}

/*
 * Return the maximum contiguous KVA range that can be accessed from this
 * physical address.  For arm64, we employ a segmented physical aperture
 * relocation table which can limit the available range for a given PA to
 * something less than the extent of physical memory.  But here, we still
 * have a flat physical aperture, so no such requirement exists.
 */
vm_map_address_t
phystokv_range(pmap_paddr_t pa, vm_size_t *max_len)
{
	vm_size_t len = gPhysSize - (pa - gPhysBase);
	if (*max_len > len) {
		*max_len = len;
	}
	assertf((pa - gPhysBase) < gPhysSize, "%s: illegal PA: 0x%lx", __func__, (unsigned long)pa);
	return pa - gPhysBase + gVirtBase;
}

vm_offset_t
ml_static_slide(
	vm_offset_t vaddr)
{
	return VM_KERNEL_SLIDE(vaddr);
}

vm_offset_t
ml_static_unslide(
	vm_offset_t vaddr)
{
	return VM_KERNEL_UNSLIDE(vaddr);
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
	ppnum_t       ppn;
	kern_return_t result = KERN_SUCCESS;

	if (vaddr < VM_MIN_KERNEL_ADDRESS) {
		return KERN_FAILURE;
	}

	assert((vaddr & (ARM_PGBYTES - 1)) == 0); /* must be page aligned */

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

	if (!(new_prot & VM_PROT_EXECUTE)) {
		arm_prot |= ARM_PTE_NX;
		arm_block_prot |= ARM_TTE_BLOCK_NX;
	}

	for (vaddr_cur = vaddr;
	    vaddr_cur < ((vaddr + size) & ~ARM_PGMASK);
	    vaddr_cur += ARM_PGBYTES) {
		ppn = pmap_find_phys(kernel_pmap, vaddr_cur);
		if (ppn != (vm_offset_t) NULL) {
			tt_entry_t     *ttp = &kernel_pmap->tte[ttenum(vaddr_cur)];
			tt_entry_t      tte = *ttp;

			if ((tte & ARM_TTE_TYPE_MASK) != ARM_TTE_TYPE_TABLE) {
				if (((tte & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_BLOCK) &&
				    ((tte & (ARM_TTE_BLOCK_APMASK | ARM_TTE_BLOCK_NX_MASK)) == arm_block_prot)) {
					/*
					 * We can support ml_static_protect on a block mapping if the mapping already has
					 * the desired protections.  We still want to run checks on a per-page basis.
					 */
					continue;
				}

				result = KERN_FAILURE;
				break;
			}

			pt_entry_t *pte_p = (pt_entry_t *) ttetokv(tte) + ptenum(vaddr_cur);
			pt_entry_t ptmp = *pte_p;

			ptmp = (ptmp & ~(ARM_PTE_APMASK | ARM_PTE_NX_MASK)) | arm_prot;
			*pte_p = ptmp;
		}
	}

	if (vaddr_cur > vaddr) {
		flush_mmu_tlb_region(vaddr, (vm_size_t)(vaddr_cur - vaddr));
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
	if (vaddr < VM_MIN_KERNEL_ADDRESS) {
		return;
	}

	assert((vaddr & (PAGE_SIZE - 1)) == 0); /* must be page aligned */

	for (vaddr_cur = vaddr;
	    vaddr_cur < trunc_page_32(vaddr + size);
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
#if     DEBUG
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
	uint32_t        count, nbytes = 0;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc))) {
			break;
		}
		if (!(cur_phys_dst = kvtophys(virtdst))) {
			break;
		}
		if (!pmap_valid_address(trunc_page_64(cur_phys_dst)) ||
		    !pmap_valid_address(trunc_page_64(cur_phys_src))) {
			break;
		}
		count = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		if (count > (PAGE_SIZE - (cur_phys_dst & PAGE_MASK))) {
			count = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		}
		if (count > size) {
			count = size;
		}

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

boolean_t
ml_validate_nofault(
	vm_offset_t virtsrc, vm_size_t size)
{
	addr64_t cur_phys_src;
	uint32_t count;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc))) {
			return FALSE;
		}
		if (!pmap_valid_address(trunc_page_64(cur_phys_src))) {
			return FALSE;
		}
		count = (uint32_t)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		if (count > size) {
			count = (uint32_t)size;
		}

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

/*
 * Stubs for CPU Stepper
 */
void
active_rt_threads(__unused boolean_t active)
{
}

void
thread_tell_urgency(__unused thread_urgency_t urgency,
    __unused uint64_t rt_period,
    __unused uint64_t rt_deadline,
    __unused uint64_t sched_latency,
    __unused thread_t nthread)
{
}

void
machine_run_count(__unused uint32_t count)
{
}

processor_t
machine_choose_processor(__unused processor_set_t pset, processor_t processor)
{
	return processor;
}

boolean_t
machine_timeout_suspended(void)
{
	return FALSE;
}

kern_return_t
ml_interrupt_prewarm(__unused uint64_t deadline)
{
	return KERN_FAILURE;
}

uint64_t
ml_get_hwclock(void)
{
	uint64_t high_first = 0;
	uint64_t high_second = 0;
	uint64_t low = 0;

	__builtin_arm_isb(ISB_SY);

	do {
		high_first = __builtin_arm_mrrc(15, 0, 14) >> 32;
		low = __builtin_arm_mrrc(15, 0, 14) & 0xFFFFFFFFULL;
		high_second = __builtin_arm_mrrc(15, 0, 14) >> 32;
	} while (high_first != high_second);

	return (high_first << 32) | (low);
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

void
ml_delay_on_yield(void)
{
}

boolean_t
ml_thread_is64bit(thread_t thread)
{
	return thread_is_64bit_addr(thread);
}

void
ml_timer_evaluate(void)
{
}

boolean_t
ml_timer_forced_evaluation(void)
{
	return FALSE;
}

uint64_t
ml_energy_stat(__unused thread_t t)
{
	return 0;
}


void
ml_gpu_stat_update(__unused uint64_t gpu_ns_delta)
{
#if CONFIG_EMBEDDED
	/*
	 * For now: update the resource coalition stats of the
	 * current thread's coalition
	 */
	task_coalition_update_gpu_stats(current_task(), gpu_ns_delta);
#endif
}

uint64_t
ml_gpu_stat(__unused thread_t t)
{
	return 0;
}

#if !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
static void
timer_state_event(boolean_t switch_to_kernel)
{
	thread_t thread = current_thread();
	if (!thread->precise_user_kernel_time) {
		return;
	}

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

uint32_t
get_arm_cpu_version(void)
{
	uint32_t value = machine_read_midr();

	/* Compose the register values into 8 bits; variant[7:4], revision[3:0]. */
	return ((value & MIDR_REV_MASK) >> MIDR_REV_SHIFT) | ((value & MIDR_VAR_MASK) >> (MIDR_VAR_SHIFT - 4));
}

boolean_t
user_cont_hwclock_allowed(void)
{
	return FALSE;
}

uint8_t
user_timebase_type(void)
{
#if __ARM_TIME__
	return USER_TIMEBASE_SPEC;
#else
	return USER_TIMEBASE_NONE;
#endif
}

/*
 * The following are required for parts of the kernel
 * that cannot resolve these functions as inlines:
 */
extern thread_t current_act(void) __attribute__((const));
thread_t
current_act(void)
{
	return current_thread_fast();
}

#undef current_thread
extern thread_t current_thread(void) __attribute__((const));
thread_t
current_thread(void)
{
	return current_thread_fast();
}

#if __ARM_USER_PROTECT__
uintptr_t
arm_user_protect_begin(thread_t thread)
{
	uintptr_t   ttbr0, asid = 0;            //  kernel asid

	ttbr0 = __builtin_arm_mrc(15, 0, 2, 0, 0);      // Get TTBR0
	if (ttbr0 != thread->machine.kptw_ttb) {
		__builtin_arm_mcr(15, 0, thread->machine.kptw_ttb, 2, 0, 0); // Set TTBR0
		__builtin_arm_mcr(15, 0, asid, 13, 0, 1); // Set CONTEXTIDR
		__builtin_arm_isb(ISB_SY);
	}
	return ttbr0;
}

void
arm_user_protect_end(thread_t thread, uintptr_t ttbr0, boolean_t disable_interrupts)
{
	if ((ttbr0 != thread->machine.kptw_ttb) && (thread->machine.uptw_ttb != thread->machine.kptw_ttb)) {
		if (disable_interrupts) {
			__asm__ volatile ("cpsid if" ::: "memory"); // Disable FIQ/IRQ
		}
		__builtin_arm_mcr(15, 0, thread->machine.uptw_ttb, 2, 0, 0); // Set TTBR0
		__builtin_arm_mcr(15, 0, thread->machine.asid, 13, 0, 1); // Set CONTEXTIDR with thread asid
		__builtin_arm_dsb(DSB_ISH);
		__builtin_arm_isb(ISB_SY);
	}
}
#endif // __ARM_USER_PROTECT__
