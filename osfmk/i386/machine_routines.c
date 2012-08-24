/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <i386/machine_cpu.h>
#include <i386/lapic.h>
#include <i386/lock.h>
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

#if DEBUG
#define DBG(x...)	kprintf("DBG: " x)
#else
#define DBG(x...)
#endif

extern void 	wakeup(void *);

static int max_cpus_initialized = 0;

unsigned int	LockTimeOut;
unsigned int	LockTimeOutTSC;
unsigned int	MutexSpin;
uint64_t	LastDebuggerEntryAllowance;
uint64_t	delay_spin_threshold;

extern uint64_t panic_restart_timeout;

boolean_t virtualized = FALSE;

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
				vm_page_wire_count--;
				freed_pages++;
			}
		}
	}
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

	istate = ((flags & EFL_IF) != 0);

	if (enable) {
		__asm__ volatile("sti;nop");

		if ((get_preemption_level() == 0) && (*ast_pending() & AST_URGENT))
			__asm__ volatile ("int $0xff");
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

/* Generate a fake interrupt */
void ml_cause_interrupt(void)
{
	panic("ml_cause_interrupt not defined yet on Intel");
}

void ml_thread_policy(
	thread_t thread,
__unused	unsigned policy_id,
	unsigned policy_info)
{
	if (policy_info & MACHINE_NETWORK_WORKLOOP) {
		spl_t		s = splsched();

		thread_lock(thread);

		set_priority(thread, thread->priority + 1);

		thread_unlock(thread);
		splx(s);
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

	current_state = ml_get_interrupts_enabled();

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

	this_cpu_datap->cpu_chud = chudxnu_cpu_alloc(boot_cpu);
	if (this_cpu_datap->cpu_chud == NULL)
		goto failed;

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
	chudxnu_cpu_free(this_cpu_datap->cpu_chud);
	console_cpu_free(this_cpu_datap->cpu_console_buf);
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

/*
 *	Routine:        ml_init_lock_timeout
 *	Function:
 */
void
ml_init_lock_timeout(void)
{
	uint64_t	abstime;
	uint32_t	mtxspin;
	uint64_t	default_timeout_ns = NSEC_PER_SEC>>2;
	uint32_t	slto;
	uint32_t	prt;

	if (PE_parse_boot_argn("slto_us", &slto, sizeof (slto)))
		default_timeout_ns = slto * NSEC_PER_USEC;

	/* LockTimeOut is absolutetime, LockTimeOutTSC is in TSC ticks */
	nanoseconds_to_absolutetime(default_timeout_ns, &abstime);
	LockTimeOut = (uint32_t) abstime;
	LockTimeOutTSC = (uint32_t) tmrCvt(abstime, tscFCvtn2t);

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
	interrupt_latency_tracker_setup();
}

/*
 * Threshold above which we should attempt to block
 * instead of spinning for clock_delay_until().
 */
void
ml_init_delay_spin_threshold(void)
{
	nanoseconds_to_absolutetime(10ULL * NSEC_PER_USEC, &delay_spin_threshold);
}

boolean_t
ml_delay_should_spin(uint64_t interval)
{
	return (interval < delay_spin_threshold) ? TRUE : FALSE;
}

/*
 * This is called from the machine-independent routine cpu_up()
 * to perform machine-dependent info updates. Defer to cpu_thread_init().
 */
void
ml_cpu_up(void)
{
	return;
}

/*
 * This is called from the machine-independent routine cpu_down()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_down(void)
{
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
  
        return (thread_is_64bit(thread));
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

#if defined(__i386__)
	/*
 	 * If 64bit this requires a mode switch (and back). 
	 */
	if (cpu_mode_is64bit())
		ml_64bit_lldt(selector);
	else
		lldt(selector);
#else
	lldt(selector);
#endif
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

void
kernel_preempt_check(void)
{
	boolean_t	intr;
	unsigned long flags;

	assert(get_preemption_level() == 0);

	__asm__ volatile("pushf; pop	%0" :  "=r" (flags));

	intr = ((flags & EFL_IF) != 0);

	if ((*ast_pending() & AST_URGENT) && intr == TRUE) {
		/*
		 * can handle interrupts and preemptions 
		 * at this point
		 */

		/*
		 * now cause the PRE-EMPTION trap
		 */
		__asm__ volatile ("int %0" :: "N" (T_PREEMPT));
	}
}

boolean_t machine_timeout_suspended(void) {
	return (virtualized || pmap_tlb_flush_timeout || spinlock_timed_out || panic_active() || mp_recent_debugger_activity());
}
