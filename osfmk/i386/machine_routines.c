/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <kern/processor.h>
#include <kern/machine.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <i386/cpu_data.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <i386/mp_events.h>
#include <i386/cpu_threads.h>
#include <i386/pmap.h>
#include <i386/misc_protos.h>
#include <i386/pmCPU.h>
#include <i386/proc_reg.h>
#include <mach/vm_param.h>
#if MACH_KDB
#include <i386/db_machdep.h>
#include <ddb/db_aout.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_expr.h>
#endif

#define MIN(a,b) ((a)<(b)? (a) : (b))

#if DEBUG
#define DBG(x...)	kprintf("DBG: " x)
#else
#define DBG(x...)
#endif

extern void	initialize_screen(Boot_Video *, unsigned int);
extern thread_t	Shutdown_context(thread_t thread, void (*doshutdown)(processor_t),processor_t  processor);
extern void 	wakeup(void *);
extern unsigned KernelRelocOffset;

static int max_cpus_initialized = 0;

unsigned int	LockTimeOut = 12500000;
unsigned int	MutexSpin = 0;

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
        *phys_addr = bounce_pool_base;
	*size      = bounce_pool_size;
}


vm_offset_t
ml_boot_ptovirt(
	vm_offset_t paddr)
{
	return (vm_offset_t)((paddr-KernelRelocOffset) | LINEAR_KERNEL_ADDRESS);
} 

vm_offset_t
ml_static_ptovirt(
	vm_offset_t paddr)
{
    return (vm_offset_t)((unsigned) paddr | LINEAR_KERNEL_ADDRESS);
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
	vm_offset_t vaddr_cur;
	ppnum_t ppn;

//	if (vaddr < VM_MIN_KERNEL_ADDRESS) return;

	assert((vaddr & (PAGE_SIZE-1)) == 0); /* must be page aligned */

	for (vaddr_cur = vaddr;
	     vaddr_cur < round_page_32(vaddr+size);
	     vaddr_cur += PAGE_SIZE) {
		ppn = pmap_find_phys(kernel_pmap, (addr64_t)vaddr_cur);
		if (ppn != (vm_offset_t)NULL) {
			pmap_remove(kernel_pmap, (addr64_t)vaddr_cur, (addr64_t)(vaddr_cur+PAGE_SIZE));
			vm_page_create(ppn,(ppn+1));
			vm_page_wire_count--;
		}
	}
}


/* virtual to physical on wired pages */
vm_offset_t ml_vtophys(
	vm_offset_t vaddr)
{
	return	kvtophys(vaddr);
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

  __asm__ volatile("pushf; popl	%0" :  "=r" (flags));
  return (flags & EFL_IF) != 0;
}

/* Set Interrupts Enabled */
boolean_t ml_set_interrupts_enabled(boolean_t enable)
{
  unsigned long flags;

  __asm__ volatile("pushf; popl	%0" :  "=r" (flags));

  if (enable) {
	ast_t		*myast;

	myast = ast_pending();

	if ( (get_preemption_level() == 0) &&  (*myast & AST_URGENT) ) {
	__asm__ volatile("sti");
          __asm__ volatile ("int $0xff");
        } else {
	  __asm__ volatile ("sti");
	}
  }
  else {
	__asm__ volatile("cli");
  }

  return (flags & EFL_IF) != 0;
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
	unsigned policy_id,
	unsigned policy_info)
{
	if (policy_id == MACHINE_GROUP)
		thread_bind(thread, master_processor);

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

	initialize_screen(0, kPEAcquireScreen);
}


void
machine_idle(void)
{
	cpu_core_t	*my_core = cpu_core();
	int		others_active;

	/*
	 * We halt this cpu thread
	 * unless kernel param idlehalt is false and no other thread
	 * in the same core is active - if so, don't halt so that this
	 * core doesn't go into a low-power mode.
	 * For 4/4, we set a null "active cr3" while idle.
	 */
	others_active = !atomic_decl_and_test(
				(long *) &my_core->active_threads, 1);
	if (idlehalt || others_active) {
		DBGLOG(cpu_handle, cpu_number(), MP_IDLE);
		MARK_CPU_IDLE(cpu_number());
		machine_idle_cstate();
		MARK_CPU_ACTIVE(cpu_number());
		DBGLOG(cpu_handle, cpu_number(), MP_UNIDLE);
	} else {
		__asm__ volatile("sti");
	}
	atomic_incl((long *) &my_core->active_threads, 1);
}

void
machine_signal_idle(
        processor_t processor)
{
	cpu_interrupt(PROCESSOR_DATA(processor, slot_num));
}

thread_t        
machine_processor_shutdown(
	thread_t               thread,
	void                   (*doshutdown)(processor_t),
	processor_t    processor)
{
        fpu_save_context(thread);
	return(Shutdown_context(thread, doshutdown, processor));
}

kern_return_t
ml_processor_register(
	cpu_id_t	cpu_id,
	uint32_t	lapic_id,
	processor_t	*processor_out,
	ipi_handler_t   *ipi_handler,
	boolean_t	boot_cpu)
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

	this_cpu_datap->cpu_id = cpu_id;
	this_cpu_datap->cpu_phys_number = lapic_id;

	this_cpu_datap->cpu_console_buf = console_cpu_alloc(boot_cpu);
	if (this_cpu_datap->cpu_console_buf == NULL)
		goto failed;

	this_cpu_datap->cpu_chud = chudxnu_cpu_alloc(boot_cpu);
	if (this_cpu_datap->cpu_chud == NULL)
		goto failed;

	if (!boot_cpu) {
		this_cpu_datap->cpu_core = cpu_thread_alloc(target_cpu);

		this_cpu_datap->cpu_pmap = pmap_cpu_alloc(boot_cpu);
		if (this_cpu_datap->cpu_pmap == NULL)
			goto failed;

		this_cpu_datap->cpu_processor = cpu_processor_alloc(boot_cpu);
		if (this_cpu_datap->cpu_processor == NULL)
			goto failed;
		processor_init(this_cpu_datap->cpu_processor, target_cpu);
	}

	*processor_out = this_cpu_datap->cpu_processor;
	*ipi_handler = NULL;

	return KERN_SUCCESS;

failed:
	cpu_processor_free(this_cpu_datap->cpu_processor);
	pmap_cpu_free(this_cpu_datap->cpu_pmap);
	chudxnu_cpu_free(this_cpu_datap->cpu_chud);
	console_cpu_free(this_cpu_datap->cpu_console_buf);
	return KERN_FAILURE;
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
	os_supports_sse = get_cr4() & CR4_XMM;
	if ((cpuid_features() & CPUID_FEATURE_MNI) && os_supports_sse)
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
			 * Note: max_cpus is the number of enable processors
			 * that ACPI found; max_ncpus is the maximum number
			 * that the kernel supports or that the "cpus="
			 * boot-arg has set. Here we take int minimum.
			 */
                        machine_info.max_cpus = MIN(max_cpus, max_ncpus);
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

	/*
	 * XXX As currently implemented for x86, LockTimeOut should be a
	 * cycle (tsc) count not an absolute time (nanoseconds) -
	 * but it's of the right order.
	 */
	nanoseconds_to_absolutetime(NSEC_PER_SEC>>2, &abstime);
	LockTimeOut = (unsigned int)abstime;

	if (PE_parse_boot_arg("mtxspin", &mtxspin)) {
		if (mtxspin > USEC_PER_SEC>>4)
			mtxspin =  USEC_PER_SEC>>4;
		nanoseconds_to_absolutetime(mtxspin*NSEC_PER_USEC, &abstime);
	} else {
		nanoseconds_to_absolutetime(10*NSEC_PER_USEC, &abstime);
	}
	MutexSpin = (unsigned int)abstime;
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

/* Stubs for pc tracing mechanism */

int *pc_trace_buf;
int pc_trace_cnt = 0;

int
set_be_bit(void)
{
  return(0);
}

int
clr_be_bit(void)
{
  return(0);
}

int
be_tracing(void)
{
  return(0);
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

/*
 * Set the worst-case time for the C4 to C2 transition.
 * The maxdelay parameter is in nanoseconds. 
 */
 
void
ml_set_maxsnoop(uint32_t maxdelay)
{
	C4C2SnoopDelay = maxdelay;	/* Set the transition time */ 
   	machine_nap_policy();		/* Adjust the current nap state */
}


/*
 * Get the worst-case time for the C4 to C2 transition.  Returns nanoseconds.
 */

unsigned
ml_get_maxsnoop(void)
{
	return C4C2SnoopDelay;		/* Set the transition time */
}


uint32_t
ml_get_maxbusdelay(void)
{
    return maxBusDelay;
}

/*
 * Set the maximum delay time allowed for snoop on the bus.
 *
 * Note that this value will be compared to the amount of time that it takes
 * to transition from a non-snooping power state (C4) to a snooping state (C2).
 * If maxBusDelay is less than C4C2SnoopDelay,
 * we will not enter the lowest power state.
 */
 
void
ml_set_maxbusdelay(uint32_t mdelay)
{
	maxBusDelay = mdelay;		/* Set the delay */
	machine_nap_policy();		/* Adjust the current nap state */
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

	/*
 	 * If 64bit this requires a mode switch (and back). 
	 */
	if (cpu_mode_is64bit())
		ml_64bit_lldt(selector);
	else
		lldt(selector);
	current_cpu_datap()->cpu_ldt = selector;	
}

void ml_fp_setvalid(boolean_t value)
{
        fp_setvalid(value);
}

#if MACH_KDB

/*
 *	Display the global msrs
 * *		
 *	ms
 */
void 
db_msr(__unused db_expr_t addr,
       __unused int have_addr,
       __unused db_expr_t count,
       __unused char *modif)
{

	uint32_t        i, msrlow, msrhigh;

	/* Try all of the first 4096 msrs */
	for (i = 0; i < 4096; i++) {
		if (!rdmsr_carefully(i, &msrlow, &msrhigh)) {
			db_printf("%08X - %08X.%08X\n", i, msrhigh, msrlow);
		}
	}

	/* Try all of the 4096 msrs at 0x0C000000 */
	for (i = 0; i < 4096; i++) {
		if (!rdmsr_carefully(0x0C000000 | i, &msrlow, &msrhigh)) {
			db_printf("%08X - %08X.%08X\n",
				0x0C000000 | i, msrhigh, msrlow);
		}
	}

	/* Try all of the 4096 msrs at 0xC0000000 */
	for (i = 0; i < 4096; i++) {
		if (!rdmsr_carefully(0xC0000000 | i, &msrlow, &msrhigh)) {
			db_printf("%08X - %08X.%08X\n",
				0xC0000000 | i, msrhigh, msrlow);
		}
	}
}

#endif
