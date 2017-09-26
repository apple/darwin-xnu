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
 *	File:	i386/cpu.c
 *
 *	cpu specific routines
 */

#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kern/machine.h>
#include <mach/processor_info.h>
#include <i386/pmap.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <i386/cpu_threads.h>
#include <i386/rtclock_protos.h>
#include <i386/cpuid.h>
#if CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif
#include <vm/vm_kern.h>
#include <kern/timer_call.h>

struct processor	processor_master;

/*ARGSUSED*/
kern_return_t
cpu_control(
	int			slot_num,
	processor_info_t	info,
	unsigned int		count)
{
	printf("cpu_control(%d,%p,%d) not implemented\n",
		slot_num, info, count);
	return (KERN_FAILURE);
}

/*ARGSUSED*/
kern_return_t
cpu_info_count(
        __unused processor_flavor_t      flavor,
	unsigned int			*count)
{
	*count = 0;
	return (KERN_FAILURE);
}

/*ARGSUSED*/
kern_return_t
cpu_info(
        processor_flavor_t      flavor,
	int			slot_num,
	processor_info_t	info,
	unsigned int		*count)
{
	printf("cpu_info(%d,%d,%p,%p) not implemented\n",
		flavor, slot_num, info, count);
	return (KERN_FAILURE);
}

void
cpu_sleep(void)
{
	cpu_data_t	*cdp = current_cpu_datap();

	PE_cpu_machine_quiesce(cdp->cpu_id);

	cpu_thread_halt();
}

void
cpu_init(void)
{
	cpu_data_t	*cdp = current_cpu_datap();

	timer_call_queue_init(&cdp->rtclock_timer.queue);
	cdp->rtclock_timer.deadline = EndOfAllTime;

	cdp->cpu_type = cpuid_cputype();
	cdp->cpu_subtype = cpuid_cpusubtype();

	i386_activate_cpu();
}

kern_return_t
cpu_start(
	int cpu)
{
	kern_return_t		ret;

	if (cpu == cpu_number()) {
		cpu_machine_init();
		return KERN_SUCCESS;
	}

	/*
	 * Try to bring the CPU back online without a reset.
	 * If the fast restart doesn't succeed, fall back to
	 * the slow way.
	 */
	ret = intel_startCPU_fast(cpu);
	if (ret != KERN_SUCCESS) {
		/*
		 * Should call out through PE.
		 * But take the shortcut here.
		 */
		ret = intel_startCPU(cpu);
	}

	if (ret != KERN_SUCCESS)
		kprintf("cpu: cpu_start(%d) returning failure!\n", cpu);

	return(ret);
}

void
cpu_exit_wait(
	int cpu)
{
    	cpu_data_t	*cdp = cpu_datap(cpu);
	boolean_t	intrs_enabled;
	uint64_t	tsc_timeout;

	/*
	 * Wait until the CPU indicates that it has stopped.
	 * Disable interrupts while the topo lock is held -- arguably
	 * this should always be done but in this instance it can lead to
	 * a timeout if long-running interrupt were to occur here.
	 */
	intrs_enabled = ml_set_interrupts_enabled(FALSE);
	mp_safe_spin_lock(&x86_topo_lock);
	/* Set a generous timeout of several seconds (in TSC ticks) */
	tsc_timeout = rdtsc64() + (10ULL * 1000 * 1000 * 1000);
	while ((cdp->lcpu.state != LCPU_HALT)
	       && (cdp->lcpu.state != LCPU_OFF)
	       && !cdp->lcpu.stopped) {
	    simple_unlock(&x86_topo_lock);
	    ml_set_interrupts_enabled(intrs_enabled);
	    cpu_pause();
	    if (rdtsc64() > tsc_timeout)
		panic("cpu_exit_wait(%d) timeout", cpu);
	    ml_set_interrupts_enabled(FALSE);
	    mp_safe_spin_lock(&x86_topo_lock);
	}
	simple_unlock(&x86_topo_lock);
	ml_set_interrupts_enabled(intrs_enabled);
}

void
cpu_machine_init(
	void)
{
	cpu_data_t	*cdp = current_cpu_datap();

	PE_cpu_machine_init(cdp->cpu_id, !cdp->cpu_boot_complete);
	cdp->cpu_boot_complete = TRUE;
	cdp->cpu_running = TRUE;
	ml_init_interrupt();

#if CONFIG_VMX
	/* initialize VMX for every CPU */
	vmx_cpu_init();
#endif
}

processor_t
cpu_processor_alloc(boolean_t is_boot_cpu)
{
	int		ret;
	processor_t	proc;

	if (is_boot_cpu)
		return &processor_master;

	ret = kmem_alloc(kernel_map, (vm_offset_t *) &proc, sizeof(*proc), VM_KERN_MEMORY_OSFMK);
	if (ret != KERN_SUCCESS)
		return NULL;

	bzero((void *) proc, sizeof(*proc));
	return proc;
}

void
cpu_processor_free(processor_t proc)
{
	if (proc != NULL && proc != &processor_master)
		kfree((void *) proc, sizeof(*proc));
}

processor_t
current_processor(void)
{
	return current_cpu_datap()->cpu_processor;
}

processor_t
cpu_to_processor(
	int			cpu)
{
	return cpu_datap(cpu)->cpu_processor;
}

ast_t *
ast_pending(void)
{
	return (&current_cpu_datap()->cpu_pending_ast);
}

cpu_type_t
slot_type(
	int		slot_num)
{
	return (cpu_datap(slot_num)->cpu_type);
}

cpu_subtype_t
slot_subtype(
	int		slot_num)
{
	return (cpu_datap(slot_num)->cpu_subtype);
}

cpu_threadtype_t
slot_threadtype(
	int		slot_num)
{
	return (cpu_datap(slot_num)->cpu_threadtype);
}

cpu_type_t
cpu_type(void)
{
	return (current_cpu_datap()->cpu_type);
}

cpu_subtype_t
cpu_subtype(void)
{
	return (current_cpu_datap()->cpu_subtype);
}

cpu_threadtype_t
cpu_threadtype(void)
{
	return (current_cpu_datap()->cpu_threadtype);
}
