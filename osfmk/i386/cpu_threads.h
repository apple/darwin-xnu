/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#ifndef _I386_CPU_THREADS_H_
#define _I386_CPU_THREADS_H_

#include <i386/mp.h>
#include <i386/cpu_data.h>

struct pmc;

typedef struct {
	int		base_cpu;	/* Number of the cpu first in core */
	int		num_threads;	/* Number of threads (logical cpus) */
	int		active_threads;	/* Number of non-halted thredas */
	struct pmc	*pmc;		/* Pointer to perfmon data */
} cpu_core_t;

#define CPU_THREAD_MASK			0x00000001
#define cpu_to_core_lapic(cpu)		(cpu_to_lapic[cpu] & ~CPU_THREAD_MASK)
#define cpu_to_core_cpu(cpu)		(lapic_to_cpu[cpu_to_core_lapic(cpu)])
#define cpu_to_logical_cpu(cpu)		(cpu_to_lapic[cpu] & CPU_THREAD_MASK)
#define cpu_is_core_cpu(cpu)		(cpu_to_logical_cpu(cpu) == 0)

#define cpu_to_core(cpu)		(cpu_datap(cpu)->cpu_core)

/* Fast access: */
#define cpu_core()			((cpu_core_t *) get_cpu_core())

#define cpu_is_same_core(cpu1,cpu2)	(cpu_to_core(cpu1) == cpu_to_core(cpu2))

extern void *cpu_thread_alloc(int);
extern void cpu_thread_init(void);
extern void cpu_thread_halt(void);

extern int idlehalt;

#endif /* _I386_CPU_THREADS_H_ */
