/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <i386/mp.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/pmap.h>
#include <i386/misc_protos.h>
#include <i386/cpu_threads.h>
#include <vm/vm_kern.h>


struct processor	processor_master;

/*ARGSUSED*/
kern_return_t
cpu_control(
	int			slot_num,
	processor_info_t	info,
	unsigned int		count)
{
	printf("cpu_control(%d,0x%x,%d) not implemented\n",
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
	printf("cpu_info(%d,%d,0x%x,0x%x) not implemented\n",
		flavor, slot_num, info, count);
	return (KERN_FAILURE);
}

void
cpu_sleep(void)
{
	cpu_data_t	*proc_info = current_cpu_datap();

	PE_cpu_machine_quiesce(proc_info->cpu_id);

	cpu_thread_halt();
}

void
cpu_init(void)
{
	cpu_data_t	*cdp = current_cpu_datap();

#ifdef	MACH_BSD
	/* FIXME */
	cdp->cpu_type = CPU_TYPE_I386;
	cdp->cpu_subtype = CPU_SUBTYPE_PENTPRO;
#else
	cdp->cpu_type = cpuid_cputype(0);
	cdp->cpu_subtype = CPU_SUBTYPE_AT386;
#endif
	cdp->cpu_running = TRUE;
}

kern_return_t
cpu_start(
	int cpu)
{
	kern_return_t		ret;

	if (cpu == cpu_number()) {
		cpu_machine_init();
		return KERN_SUCCESS;
	} else {
		/*
		 * Should call out through PE.
		 * But take the shortcut here.
		 */
		ret = intel_startCPU(cpu);
		return(ret);
	}
}

void
cpu_exit_wait(
	__unused int cpu)
{
}

void
cpu_machine_init(
	void)
{
	int	cpu;

	cpu = get_cpu_number();
	PE_cpu_machine_init(cpu_datap(cpu)->cpu_id, TRUE);
#if 0
	if (cpu_datap(cpu)->hibernate)
	{
	    cpu_datap(cpu)->hibernate = 0;
	    hibernate_machine_init();
	}
#endif
	ml_init_interrupt();
}

processor_t
cpu_processor_alloc(boolean_t is_boot_cpu)
{
	int		ret;
	processor_t	proc;

	if (is_boot_cpu)
		return &processor_master;

	ret = kmem_alloc(kernel_map, (vm_offset_t *) &proc, sizeof(*proc));
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
