/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <i386/machine_routines.h>
#include <i386/io_map_entries.h>
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/thread_act.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <i386/mp_events.h>

static int max_cpus_initialized = 0;

#define MAX_CPUS_SET    0x1
#define MAX_CPUS_WAIT   0x2

/* IO memory map services */

/* Map memory map IO space */
vm_offset_t ml_io_map(
	vm_offset_t phys_addr, 
	vm_size_t size)
{
	return(io_map(phys_addr,size));
}

/* boot memory allocation */
vm_offset_t ml_static_malloc(
	vm_size_t size)
{
	return((vm_offset_t)NULL);
}

vm_offset_t
ml_static_ptovirt(
	vm_offset_t paddr)
{
	return phystokv(paddr);
} 

void
ml_static_mfree(
        vm_offset_t vaddr,
        vm_size_t size)
{
	return;
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

 if (enable)
	__asm__ volatile("sti");
  else
	__asm__ volatile("cli");

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
	DBGLOG(cpu_handle, cpu_number(), MP_IDLE);
	__asm__ volatile("sti; hlt": : :"memory");
	__asm__ volatile("cli");
	DBGLOG(cpu_handle, cpu_number(), MP_UNIDLE);
}

void
machine_signal_idle(
        processor_t processor)
{
	cpu_interrupt(processor->slot_num);
}

kern_return_t
ml_processor_register(
	cpu_id_t	cpu_id,
	uint32_t	lapic_id,
	processor_t	*processor,
	ipi_handler_t   *ipi_handler,
	boolean_t	boot_cpu)
{
	kern_return_t	ret;
	int		target_cpu;

	if (cpu_register(&target_cpu) != KERN_SUCCESS)
		return KERN_FAILURE;

	assert((boot_cpu && (target_cpu == 0)) ||
	      (!boot_cpu && (target_cpu != 0)));

	lapic_cpu_map(lapic_id, target_cpu);
	cpu_data[target_cpu].cpu_id = cpu_id;
	cpu_data[target_cpu].cpu_phys_number = lapic_id;
	*processor = cpu_to_processor(target_cpu);
	*ipi_handler = NULL;

	return KERN_SUCCESS;
}

void
ml_cpu_get_info(ml_cpu_info_t *cpu_info)
{
	boolean_t	os_supports_sse;
	i386_cpu_info_t *cpuid_infop;

	if (cpu_info == NULL)
		return;
 
	/*
	 * Are we supporting XMM/SSE/SSE2?
	 * As distinct from whether the cpu has these capabilities.
	 */
	os_supports_sse = get_cr4() & CR4_XMM;
	if ((cpuid_features() & CPUID_FEATURE_SSE2) && os_supports_sse)
		cpu_info->vector_unit = 4;
	else if ((cpuid_features() & CPUID_FEATURE_SSE) && os_supports_sse)
		cpu_info->vector_unit = 3;
	else if (cpuid_features() & CPUID_FEATURE_MMX)
		cpu_info->vector_unit = 2;
	else
		cpu_info->vector_unit = 0;

	cpuid_infop  = cpuid_info();

	cpu_info->cache_line_size = cpuid_infop->cache_linesize; 

	cpu_info->l1_icache_size = cpuid_infop->cache_size[L1I];
	cpu_info->l1_dcache_size = cpuid_infop->cache_size[L1D];
  
	cpu_info->l2_settings = 1;
	cpu_info->l2_cache_size = cpuid_infop->cache_size[L2U];

	/* XXX No L3 */
	cpu_info->l3_settings = 0;
	cpu_info->l3_cache_size = 0xFFFFFFFF;
}

void
ml_init_max_cpus(unsigned long max_cpus)
{
        boolean_t current_state;

        current_state = ml_set_interrupts_enabled(FALSE);
        if (max_cpus_initialized != MAX_CPUS_SET) {
                if (max_cpus > 0 && max_cpus < NCPUS)
                        machine_info.max_cpus = max_cpus;
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

/* Stubs for pc tracing mechanism */

int *pc_trace_buf;
int pc_trace_cnt = 0;

int
set_be_bit()
{
  return(0);
}

int
clr_be_bit()
{
  return(0);
}

int
be_tracing()
{
  return(0);
}

#undef current_act
thread_act_t
current_act(void)
{               
	return(current_act_fast());
} 

#undef current_thread
thread_t
current_thread(void)
{
  return(current_act_fast());
}
