/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <i386/machine_routines.h>
#include <i386/io_map_entries.h>
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <mach/processor.h>
#include <kern/processor.h>
#include <kern/machine.h>

#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/policy_internal.h>

#include <prng/random.h>
#include <i386/machine_cpu.h>
#include <i386/lapic.h>
#include <i386/bit_routines.h>
#include <i386/mp_events.h>
#include <i386/pmCPU.h>
#include <i386/trap.h>
#include <i386/tsc.h>
#include <i386/cpu_threads.h>
#include <i386/proc_reg.h>
#include <mach/vm_param.h>
#include <i386/pmap.h>
#include <i386/pmap_internal.h>
#include <i386/misc_protos.h>
#include <kern/timer_queue.h>
#if KPC
#include <kern/kpc.h>
#endif
#include <architecture/i386/pio.h>
#include <i386/cpu_data.h>
#if DEBUG
#define DBG(x...)	kprintf("DBG: " x)
#else
#define DBG(x...)
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

extern void 	wakeup(void *);

static int max_cpus_initialized = 0;

uint64_t	LockTimeOut;
uint64_t	TLBTimeOut;
uint64_t	LockTimeOutTSC;
uint32_t	LockTimeOutUsec;
uint64_t	MutexSpin;
uint64_t	LastDebuggerEntryAllowance;
uint64_t	delay_spin_threshold;

extern uint64_t panic_restart_timeout;

boolean_t virtualized = FALSE;

decl_simple_lock_data(static,  ml_timer_evaluation_slock);
uint32_t ml_timer_eager_evaluations;
uint64_t ml_timer_eager_evaluation_max;
static boolean_t ml_timer_evaluation_in_progress = FALSE;


#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

/* IO memory map services */

/* Map memory map IO space */
vm_offset_t ml_io_map(
	vm_offset_t phys_addr, 
	vm_size_t size)
{
	return(io_map(phys_addr,size,VM_WIMG_IO));
}

/* boot memory allocation */
vm_offset_t ml_static_malloc(
			     __unused vm_size_t size)
{
	return((vm_offset_t)NULL);
}


void ml_get_bouncepool_info(vm_offset_t *phys_addr, vm_size_t *size)
{
        *phys_addr = 0;
	*size      = 0;
}


vm_offset_t
ml_static_ptovirt(
	vm_offset_t paddr)
{
#if defined(__x86_64__)
	return (vm_offset_t)(((unsigned long) paddr) | VM_MIN_KERNEL_ADDRESS);
#else
	return (vm_offset_t)((paddr) | LINEAR_KERNEL_ADDRESS);
#endif
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


/*
 *	Routine:        ml_static_mfree
 *	Function:
 */
void
ml_static_mfree(
	vm_offset_t vaddr,
	vm_size_t size)
{
	addr64_t vaddr_cur;
	ppnum_t ppn;
	uint32_t freed_pages = 0;
	assert(vaddr >= VM_MIN_KERNEL_ADDRESS);

	assert((vaddr & (PAGE_SIZE-1)) == 0); /* must be page aligned */

	for (vaddr_cur = vaddr;
 	     vaddr_cur < round_page_64(vaddr+size);
	     vaddr_cur += PAGE_SIZE) {
		ppn = pmap_find_phys(kernel_pmap, vaddr_cur);
		if (ppn != (vm_offset_t)NULL) {
		        kernel_pmap->stats.resident_count++;
			if (kernel_pmap->stats.resident_count >
			    kernel_pmap->stats.resident_max) {
				kernel_pmap->stats.resident_max =
					kernel_pmap->stats.resident_count;
			}
			pmap_remove(kernel_pmap, vaddr_cur, vaddr_cur+PAGE_SIZE);
			assert(pmap_valid_page(ppn));
			if (IS_MANAGED_PAGE(ppn)) {
				vm_page_create(ppn,(ppn+1));
				freed_pages++;
			}
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
vm_offset_t ml_vtophys(
	vm_offset_t vaddr)
{
	return	(vm_offset_t)kvtophys(vaddr);
}

/*
 *	Routine:        ml_nofault_copy
 *	Function:	Perform a physical mode copy if the source and
 *			destination have valid translations in the kernel pmap.
 *			If translations are present, they are assumed to
 *			be wired; i.e. no attempt is made to guarantee that the
 *			translations obtained remained valid for
 *			the duration of the copy process.
 */

vm_size_t ml_nofault_copy(
	vm_offset_t virtsrc, vm_offset_t virtdst, vm_size_t size)
{
	addr64_t cur_phys_dst, cur_phys_src;
	uint32_t count, nbytes = 0;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc)))
			break;
		if (!(cur_phys_dst = kvtophys(virtdst)))
			break;
		if (!pmap_valid_page(i386_btop(cur_phys_dst)) || !pmap_valid_page(i386_btop(cur_phys_src)))
			break;
		count = (uint32_t)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		if (count > (PAGE_SIZE - (cur_phys_dst & PAGE_MASK)))
			count = (uint32_t)(PAGE_SIZE - (cur_phys_dst & PAGE_MASK));
		if (count > size)
			count = (uint32_t)size;

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
		if (!pmap_valid_page(i386_btop(cur_phys_src)))
			return FALSE;
		count = (uint32_t)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		if (count > size)
			count = (uint32_t)size;

		virtsrc += count;
		size -= count;
	}

	return TRUE;
}

/* Interrupt handling */

/* Initialize Interrupts */
void ml_init_interrupt(void)
{
	(void) ml_set_interrupts_enabled(TRUE);
}


/* Get Interrupts Enabled */
boolean_t ml_get_interrupts_enabled(void)
{
  unsigned long flags;

  __asm__ volatile("pushf; pop	%0" :  "=r" (flags));
  return (flags & EFL_IF) != 0;
}

/* Set Interrupts Enabled */
boolean_t ml_set_interrupts_enabled(boolean_t enable)
{
	unsigned long flags;
	boolean_t istate;
	
	__asm__ volatile("pushf; pop	%0" :  "=r" (flags));

	assert(get_interrupt_level() ? (enable == FALSE) : TRUE);

	istate = ((flags & EFL_IF) != 0);

	if (enable) {
		__asm__ volatile("sti;nop");

		if ((get_preemption_level() == 0) && (*ast_pending() & AST_URGENT))
			__asm__ volatile ("int %0" :: "N" (T_PREEMPT));
	}
	else {
		if (istate)
			__asm__ volatile("cli");
	}

	return istate;
}

/* Check if running at interrupt context */
boolean_t ml_at_interrupt_context(void)
{
	return get_interrupt_level() != 0;
}

void ml_get_power_state(boolean_t *icp, boolean_t *pidlep) {
	*icp = (get_interrupt_level() != 0);
	/* These will be technically inaccurate for interrupts that occur
	 * successively within a single "idle exit" event, but shouldn't
	 * matter statistically.
	 */
	*pidlep = (current_cpu_datap()->lcpu.package->num_idle == topoParms.nLThreadsPerPackage);
}

/* Generate a fake interrupt */
void ml_cause_interrupt(void)
{
	panic("ml_cause_interrupt not defined yet on Intel");
}

/*
 * TODO: transition users of this to kernel_thread_start_priority
 * ml_thread_policy is an unsupported KPI
 */
void ml_thread_policy(
	thread_t thread,
__unused	unsigned policy_id,
	unsigned policy_info)
{
	if (policy_info & MACHINE_NETWORK_WORKLOOP) {
		thread_precedence_policy_data_t info;
		__assert_only kern_return_t kret;

		info.importance = 1;

		kret = thread_policy_set_internal(thread, THREAD_PRECEDENCE_POLICY,
		                                                (thread_policy_t)&info,
		                                                THREAD_PRECEDENCE_POLICY_COUNT);
		assert(kret == KERN_SUCCESS);
	}
}

/* Initialize Interrupts */
void ml_install_interrupt_handler(
	void *nub,
	int source,
	void *target,
	IOInterruptHandler handler,
	void *refCon)  
{
	boolean_t current_state;

	current_state = ml_set_interrupts_enabled(FALSE);

	PE_install_interrupt_handler(nub, source, target,
	                             (IOInterruptHandler) handler, refCon);

	(void) ml_set_interrupts_enabled(current_state);

	initialize_screen(NULL, kPEAcquireScreen);
}


void
machine_signal_idle(
        processor_t processor)
{
	cpu_interrupt(processor->cpu_id);
}

void
machine_signal_idle_deferred(
	__unused processor_t processor)
{
	panic("Unimplemented");
}

void
machine_signal_idle_cancel(
	__unused processor_t processor)
{
	panic("Unimplemented");
}

static kern_return_t
register_cpu(
        uint32_t        lapic_id,
	processor_t     *processor_out,
	boolean_t       boot_cpu )
{
	int		target_cpu;
	cpu_data_t	*this_cpu_datap;

	this_cpu_datap = cpu_data_alloc(boot_cpu);
	if (this_cpu_datap == NULL) {
		return KERN_FAILURE;
	}
	target_cpu = this_cpu_datap->cpu_number;
	assert((boot_cpu && (target_cpu == 0)) ||
	      (!boot_cpu && (target_cpu != 0)));

	lapic_cpu_map(lapic_id, target_cpu);

	/* The cpu_id is not known at registration phase. Just do
	 * lapic_id for now 
	 */
	this_cpu_datap->cpu_phys_number = lapic_id;

	this_cpu_datap->cpu_console_buf = console_cpu_alloc(boot_cpu);
	if (this_cpu_datap->cpu_console_buf == NULL)
		goto failed;

#if KPC
	if (kpc_register_cpu(this_cpu_datap) != TRUE)
		goto failed;
#endif

	if (!boot_cpu) {
		cpu_thread_alloc(this_cpu_datap->cpu_number);
		if (this_cpu_datap->lcpu.core == NULL)
			goto failed;

#if NCOPY_WINDOWS > 0
		this_cpu_datap->cpu_pmap = pmap_cpu_alloc(boot_cpu);
		if (this_cpu_datap->cpu_pmap == NULL)
			goto failed;
#endif

		this_cpu_datap->cpu_processor = cpu_processor_alloc(boot_cpu);
		if (this_cpu_datap->cpu_processor == NULL)
			goto failed;
		/*
		 * processor_init() deferred to topology start
		 * because "slot numbers" a.k.a. logical processor numbers
	 	 * are not yet finalized.
		 */
	}

	*processor_out = this_cpu_datap->cpu_processor;

	return KERN_SUCCESS;

failed:
	cpu_processor_free(this_cpu_datap->cpu_processor);
#if NCOPY_WINDOWS > 0
	pmap_cpu_free(this_cpu_datap->cpu_pmap);
#endif
	console_cpu_free(this_cpu_datap->cpu_console_buf);
#if KPC
	kpc_unregister_cpu(this_cpu_datap);
#endif /* KPC */

	return KERN_FAILURE;
}


kern_return_t
ml_processor_register(
        cpu_id_t        cpu_id,
        uint32_t        lapic_id,
        processor_t     *processor_out,
        boolean_t       boot_cpu,
	boolean_t       start )
{
    static boolean_t done_topo_sort = FALSE;
    static uint32_t num_registered = 0;

    /* Register all CPUs first, and track max */
    if( start == FALSE )
    {
	num_registered++;

	DBG( "registering CPU lapic id %d\n", lapic_id );

	return register_cpu( lapic_id, processor_out, boot_cpu );
    }

    /* Sort by topology before we start anything */
    if( !done_topo_sort )
    {
	DBG( "about to start CPUs. %d registered\n", num_registered );

	cpu_topology_sort( num_registered );
	done_topo_sort = TRUE;
    }

    /* Assign the cpu ID */
    uint32_t cpunum = -1;
    cpu_data_t	*this_cpu_datap = NULL;

    /* find cpu num and pointer */
    cpunum = ml_get_cpuid( lapic_id );

    if( cpunum == 0xFFFFFFFF ) /* never heard of it? */
	panic( "trying to start invalid/unregistered CPU %d\n", lapic_id );

    this_cpu_datap = cpu_datap(cpunum);

    /* fix the CPU id */
    this_cpu_datap->cpu_id = cpu_id;

    /* allocate and initialize other per-cpu structures */
    if (!boot_cpu) {
	mp_cpus_call_cpu_init(cpunum);
	early_random_cpu_init(cpunum);
    }

    /* output arg */
    *processor_out = this_cpu_datap->cpu_processor;

    /* OK, try and start this CPU */
    return cpu_topology_start_cpu( cpunum );
}


void
ml_cpu_get_info(ml_cpu_info_t *cpu_infop)
{
	boolean_t	os_supports_sse;
	i386_cpu_info_t *cpuid_infop;

	if (cpu_infop == NULL)
		return;
 
	/*
	 * Are we supporting MMX/SSE/SSE2/SSE3?
	 * As distinct from whether the cpu has these capabilities.
	 */
	os_supports_sse = !!(get_cr4() & CR4_OSXMM);

	if (ml_fpu_avx_enabled())
		cpu_infop->vector_unit = 9;
	else if ((cpuid_features() & CPUID_FEATURE_SSE4_2) && os_supports_sse)
		cpu_infop->vector_unit = 8;
	else if ((cpuid_features() & CPUID_FEATURE_SSE4_1) && os_supports_sse)
		cpu_infop->vector_unit = 7;
	else if ((cpuid_features() & CPUID_FEATURE_SSSE3) && os_supports_sse)
		cpu_infop->vector_unit = 6;
	else if ((cpuid_features() & CPUID_FEATURE_SSE3) && os_supports_sse)
		cpu_infop->vector_unit = 5;
	else if ((cpuid_features() & CPUID_FEATURE_SSE2) && os_supports_sse)
		cpu_infop->vector_unit = 4;
	else if ((cpuid_features() & CPUID_FEATURE_SSE) && os_supports_sse)
		cpu_infop->vector_unit = 3;
	else if (cpuid_features() & CPUID_FEATURE_MMX)
		cpu_infop->vector_unit = 2;
	else
		cpu_infop->vector_unit = 0;

	cpuid_infop  = cpuid_info();

	cpu_infop->cache_line_size = cpuid_infop->cache_linesize; 

	cpu_infop->l1_icache_size = cpuid_infop->cache_size[L1I];
	cpu_infop->l1_dcache_size = cpuid_infop->cache_size[L1D];
  
        if (cpuid_infop->cache_size[L2U] > 0) {
            cpu_infop->l2_settings = 1;
            cpu_infop->l2_cache_size = cpuid_infop->cache_size[L2U];
        } else {
            cpu_infop->l2_settings = 0;
            cpu_infop->l2_cache_size = 0xFFFFFFFF;
        }

        if (cpuid_infop->cache_size[L3U] > 0) {
            cpu_infop->l3_settings = 1;
            cpu_infop->l3_cache_size = cpuid_infop->cache_size[L3U];
        } else {
            cpu_infop->l3_settings = 0;
            cpu_infop->l3_cache_size = 0xFFFFFFFF;
        }
}

void
ml_init_max_cpus(unsigned long max_cpus)
{
        boolean_t current_state;

        current_state = ml_set_interrupts_enabled(FALSE);
        if (max_cpus_initialized != MAX_CPUS_SET) {
                if (max_cpus > 0 && max_cpus <= MAX_CPUS) {
			/*
			 * Note: max_cpus is the number of enabled processors
			 * that ACPI found; max_ncpus is the maximum number
			 * that the kernel supports or that the "cpus="
			 * boot-arg has set. Here we take int minimum.
			 */
                        machine_info.max_cpus = (integer_t)MIN(max_cpus, max_ncpus);
		}
                if (max_cpus_initialized == MAX_CPUS_WAIT)
                        wakeup((event_t)&max_cpus_initialized);
                max_cpus_initialized = MAX_CPUS_SET;
        }
        (void) ml_set_interrupts_enabled(current_state);
}

int
ml_get_max_cpus(void)
{
        boolean_t current_state;

        current_state = ml_set_interrupts_enabled(FALSE);
        if (max_cpus_initialized != MAX_CPUS_SET) {
                max_cpus_initialized = MAX_CPUS_WAIT;
                assert_wait((event_t)&max_cpus_initialized, THREAD_UNINT);
                (void)thread_block(THREAD_CONTINUE_NULL);
        }
        (void) ml_set_interrupts_enabled(current_state);
        return(machine_info.max_cpus);
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

/*
 *	Routine:        ml_init_lock_timeout
 *	Function:
 */
void
ml_init_lock_timeout(void)
{
	uint64_t	abstime;
	uint32_t	mtxspin;
#if DEVELOPMENT || DEBUG
	uint64_t	default_timeout_ns = NSEC_PER_SEC>>2;
#else
	uint64_t	default_timeout_ns = NSEC_PER_SEC>>1;
#endif
	uint32_t	slto;
	uint32_t	prt;

	if (PE_parse_boot_argn("slto_us", &slto, sizeof (slto)))
		default_timeout_ns = slto * NSEC_PER_USEC;

	/*
	 * LockTimeOut is absolutetime, LockTimeOutTSC is in TSC ticks,
	 * and LockTimeOutUsec is in microseconds and it's 32-bits.
	 */
	LockTimeOutUsec = (uint32_t) (default_timeout_ns / NSEC_PER_USEC);
	nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
	LockTimeOut = abstime;
	LockTimeOutTSC = tmrCvt(abstime, tscFCvtn2t);

	/*
	 * TLBTimeOut dictates the TLB flush timeout period. It defaults to
	 * LockTimeOut but can be overriden separately. In particular, a
	 * zero value inhibits the timeout-panic and cuts a trace evnt instead
	 * - see pmap_flush_tlbs().
	 */
	if (PE_parse_boot_argn("tlbto_us", &slto, sizeof (slto))) {
		default_timeout_ns = slto * NSEC_PER_USEC;
		nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
		TLBTimeOut = (uint32_t) abstime;
	} else {
		TLBTimeOut = LockTimeOut;
	}

#if DEVELOPMENT || DEBUG
	reportphyreaddelayabs = LockTimeOut >> 1;
#endif
	if (PE_parse_boot_argn("phyreadmaxus", &slto, sizeof (slto))) {
		default_timeout_ns = slto * NSEC_PER_USEC;
		nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
		reportphyreaddelayabs = abstime;
	}

	if (PE_parse_boot_argn("mtxspin", &mtxspin, sizeof (mtxspin))) {
		if (mtxspin > USEC_PER_SEC>>4)
			mtxspin =  USEC_PER_SEC>>4;
		nanoseconds_to_absolutetime(mtxspin*NSEC_PER_USEC, &abstime);
	} else {
		nanoseconds_to_absolutetime(10*NSEC_PER_USEC, &abstime);
	}
	MutexSpin = (unsigned int)abstime;

	nanoseconds_to_absolutetime(4ULL * NSEC_PER_SEC, &LastDebuggerEntryAllowance);
	if (PE_parse_boot_argn("panic_restart_timeout", &prt, sizeof (prt)))
		nanoseconds_to_absolutetime(prt * NSEC_PER_SEC, &panic_restart_timeout);

	virtualized = ((cpuid_features() & CPUID_FEATURE_VMM) != 0);
	if (virtualized) {
		int	vti;
		
		if (!PE_parse_boot_argn("vti", &vti, sizeof (vti)))
			vti = 6;
		printf("Timeouts adjusted for virtualization (<<%d)\n", vti);
		kprintf("Timeouts adjusted for virtualization (<<%d):\n", vti);
#define VIRTUAL_TIMEOUT_INFLATE64(_timeout)			\
MACRO_BEGIN							\
	kprintf("%24s: 0x%016llx ", #_timeout, _timeout);	\
	_timeout <<= vti;					\
	kprintf("-> 0x%016llx\n",  _timeout);			\
MACRO_END
#define VIRTUAL_TIMEOUT_INFLATE32(_timeout)			\
MACRO_BEGIN							\
	kprintf("%24s:         0x%08x ", #_timeout, _timeout);	\
	if ((_timeout <<vti) >> vti == _timeout)		\
		_timeout <<= vti;				\
	else							\
		_timeout = ~0; /* cap rather than overflow */	\
	kprintf("-> 0x%08x\n",  _timeout);			\
MACRO_END
		VIRTUAL_TIMEOUT_INFLATE32(LockTimeOutUsec);
		VIRTUAL_TIMEOUT_INFLATE64(LockTimeOut);
		VIRTUAL_TIMEOUT_INFLATE64(LockTimeOutTSC);
		VIRTUAL_TIMEOUT_INFLATE64(TLBTimeOut);
		VIRTUAL_TIMEOUT_INFLATE64(MutexSpin);
		VIRTUAL_TIMEOUT_INFLATE64(reportphyreaddelayabs);
	}

	interrupt_latency_tracker_setup();
	simple_lock_init(&ml_timer_evaluation_slock, 0);
}

/*
 * Threshold above which we should attempt to block
 * instead of spinning for clock_delay_until().
 */

void
ml_init_delay_spin_threshold(int threshold_us)
{
	nanoseconds_to_absolutetime(threshold_us * NSEC_PER_USEC, &delay_spin_threshold);
}

boolean_t
ml_delay_should_spin(uint64_t interval)
{
	return (interval < delay_spin_threshold) ? TRUE : FALSE;
}

void ml_delay_on_yield(void) {}

/*
 * This is called from the machine-independent layer
 * to perform machine-dependent info updates. Defer to cpu_thread_init().
 */
void
ml_cpu_up(void)
{
	return;
}

/*
 * This is called from the machine-independent layer
 * to perform machine-dependent info updates.
 */
void
ml_cpu_down(void)
{
	i386_deactivate_cpu();

	return;
}

/*
 * The following are required for parts of the kernel
 * that cannot resolve these functions as inlines:
 */
extern thread_t current_act(void);
thread_t
current_act(void)
{
  return(current_thread_fast());
}

#undef current_thread
extern thread_t current_thread(void);
thread_t
current_thread(void)
{
  return(current_thread_fast());
}


boolean_t ml_is64bit(void) {

        return (cpu_mode_is64bit());
}


boolean_t ml_thread_is64bit(thread_t thread) {
  
        return (thread_is_64bit_addr(thread));
}


boolean_t ml_state_is64bit(void *saved_state) {

	return is_saved_state64(saved_state);
}

void ml_cpu_set_ldt(int selector)
{
	/*
	 * Avoid loading the LDT
	 * if we're setting the KERNEL LDT and it's already set.
	 */
	if (selector == KERNEL_LDT &&
	    current_cpu_datap()->cpu_ldt == KERNEL_LDT)
		return;

	lldt(selector);
	current_cpu_datap()->cpu_ldt = selector;
}

void ml_fp_setvalid(boolean_t value)
{
        fp_setvalid(value);
}

uint64_t ml_cpu_int_event_time(void)
{
	return current_cpu_datap()->cpu_int_event_time;
}

vm_offset_t ml_stack_remaining(void)
{
	uintptr_t local = (uintptr_t) &local;

	if (ml_at_interrupt_context() != 0) {
	    return (local - (current_cpu_datap()->cpu_int_stack_top - INTSTACK_SIZE));
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
		return current_cpu_datap()->cpu_int_stack_top - INTSTACK_SIZE;
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

void
kernel_preempt_check(void)
{
	boolean_t	intr;
	unsigned long flags;

	assert(get_preemption_level() == 0);

	if (__improbable(*ast_pending() & AST_URGENT)) {
		/*
		 * can handle interrupts and preemptions 
		 * at this point
		 */
		__asm__ volatile("pushf; pop	%0" :  "=r" (flags));

		intr = ((flags & EFL_IF) != 0);

		/*
		 * now cause the PRE-EMPTION trap
		 */
		if (intr == TRUE){
			__asm__ volatile ("int %0" :: "N" (T_PREEMPT));
		}
	}
}

boolean_t machine_timeout_suspended(void) {
	return (pmap_tlb_flush_timeout || spinlock_timed_out || panic_active() || mp_recent_debugger_activity() || ml_recent_wake());
}

/* Eagerly evaluate all pending timer and thread callouts
 */
void ml_timer_evaluate(void) {
	KERNEL_DEBUG_CONSTANT(DECR_TIMER_RESCAN|DBG_FUNC_START, 0, 0, 0, 0, 0);

	uint64_t te_end, te_start = mach_absolute_time();
	simple_lock(&ml_timer_evaluation_slock);
	ml_timer_evaluation_in_progress = TRUE;
	thread_call_delayed_timer_rescan_all();
	mp_cpus_call(CPUMASK_ALL, ASYNC, timer_queue_expire_rescan, NULL);
	ml_timer_evaluation_in_progress = FALSE;
	ml_timer_eager_evaluations++;
	te_end = mach_absolute_time();
	ml_timer_eager_evaluation_max = MAX(ml_timer_eager_evaluation_max, (te_end - te_start));
	simple_unlock(&ml_timer_evaluation_slock);

	KERNEL_DEBUG_CONSTANT(DECR_TIMER_RESCAN|DBG_FUNC_END, 0, 0, 0, 0, 0);
}

boolean_t
ml_timer_forced_evaluation(void) {
	return ml_timer_evaluation_in_progress;
}

/* 32-bit right-rotate n bits */
static inline uint32_t ror32(uint32_t val, const unsigned int n)
{	
	__asm__ volatile("rorl %%cl,%0" : "=r" (val) : "0" (val), "c" (n));
	return val;
}

void
ml_entropy_collect(void)
{
	uint32_t	tsc_lo, tsc_hi;
	uint32_t	*ep;

	assert(cpu_number() == master_cpu);

	/* update buffer pointer cyclically */
	if (EntropyData.index_ptr - EntropyData.buffer == ENTROPY_BUFFER_SIZE)
		ep = EntropyData.index_ptr = EntropyData.buffer;
	else
		ep = EntropyData.index_ptr++;

	rdtsc_nofence(tsc_lo, tsc_hi);
	*ep = ror32(*ep, 9) ^ tsc_lo;
}

uint64_t
ml_energy_stat(__unused thread_t t) {
	return 0;
}

void
ml_gpu_stat_update(uint64_t gpu_ns_delta) {
	current_thread()->machine.thread_gpu_ns += gpu_ns_delta;
}

uint64_t
ml_gpu_stat(thread_t t) {
	return t->machine.thread_gpu_ns;
}

int plctrace_enabled = 0;

void _disable_preemption(void) {
	disable_preemption_internal();
}

void _enable_preemption(void) {
	enable_preemption_internal();
}

void plctrace_disable(void) {
	plctrace_enabled = 0;
}

static boolean_t ml_quiescing;

void ml_set_is_quiescing(boolean_t quiescing)
{
    assert(FALSE == ml_get_interrupts_enabled());
    ml_quiescing = quiescing;
}

boolean_t ml_is_quiescing(void)
{
    assert(FALSE == ml_get_interrupts_enabled());
    return (ml_quiescing);
}

uint64_t ml_get_booter_memory_size(void)
{
    return (0);
}
