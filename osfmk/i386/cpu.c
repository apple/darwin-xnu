/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *	File:	i386/cpu.c
 *
 *	cpu specific routines
 */

#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/processor.h>
#include <mach/processor_info.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/mp_desc.h>

cpu_data_t	cpu_data[NCPUS];
int		real_ncpus = 0;
int		wncpu = NCPUS;

/*ARGSUSED*/
kern_return_t
cpu_control(
	int			slot_num,
	processor_info_t	info,
	unsigned int		count)
{
	printf("cpu_control not implemented\n");
	return (KERN_FAILURE);
}

/*ARGSUSED*/
kern_return_t
cpu_info_count(
        processor_flavor_t      flavor,
	unsigned int		*count)
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
	printf("cpu_info not implemented\n");
	return (KERN_FAILURE);
}

void
cpu_sleep()
{
	printf("cpu_sleep not implemented\n");
}

void
cpu_init()
{
	int	my_cpu = get_cpu_number();

	machine_slot[my_cpu].is_cpu = TRUE;
	machine_slot[my_cpu].running = TRUE;
#ifdef	MACH_BSD
	/* FIXME */
	machine_slot[my_cpu].cpu_type = CPU_TYPE_I386;
	machine_slot[my_cpu].cpu_subtype = CPU_SUBTYPE_PENTPRO;
#else
	machine_slot[my_cpu].cpu_type = cpuid_cputype(0);
	machine_slot[my_cpu].cpu_subtype = CPU_SUBTYPE_AT386;
#endif

#if	NCPUS > 1
	mp_desc_init(my_cpu);
#endif	/* NCPUS */
}

kern_return_t
cpu_register(
	int *target_cpu)
{
	int cpu;

	if (real_ncpus == 0) {
		/*
		 * Special case for the boot processor,
		 * it has been pre-registered by cpu_init(); 
		 */
		*target_cpu = 0;
		real_ncpus++;
		return KERN_SUCCESS;
	}

	/* 
	 * TODO: 
	 * - Run cpu_register() in exclusion mode 
	 */

	*target_cpu = -1;
	for(cpu=0; cpu < wncpu; cpu++) {
		if(!machine_slot[cpu].is_cpu) {
			machine_slot[cpu].is_cpu = TRUE;
#ifdef	MACH_BSD
			/* FIXME */
			machine_slot[cpu].cpu_type = CPU_TYPE_I386;
			machine_slot[cpu].cpu_subtype = CPU_SUBTYPE_PENTPRO;
#else
			machine_slot[cpu].cpu_type = cpuid_cputype(0);
			machine_slot[cpu].cpu_subtype = CPU_SUBTYPE_AT386;
#endif
			*target_cpu = cpu;
			break;
		}
	}

	if (*target_cpu != -1) {
		real_ncpus++;
		return KERN_SUCCESS;
	} else
		return KERN_FAILURE;
}

kern_return_t
cpu_start(
	int cpu)
{
	kern_return_t		ret;

	if (cpu == cpu_number()) {
		PE_cpu_machine_init(cpu_data[cpu].cpu_id, TRUE);
		ml_init_interrupt();
		cpu_data[cpu].cpu_status = 1;
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
cpu_machine_init(
	void)
{
	int	cpu;

	cpu = get_cpu_number();
	PE_cpu_machine_init(cpu_data[cpu].cpu_id, TRUE);
	ml_init_interrupt();
	cpu_data[cpu].cpu_status = 1;
}

