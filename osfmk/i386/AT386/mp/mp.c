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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

/*
 */

#include <cpus.h>
#include <mp_v1_1.h>

#if NCPUS > 1

#include <types.h>
#include <mach/machine.h>
#include <kern/lock.h>
#include <kern/cpu_data.h>
#include <kern/processor.h>
#include <kern/misc_protos.h>
#include <kern/machine.h>
#include <i386/db_machdep.h>
#include <ddb/db_run.h>
#include <i386/AT386/mp/mp.h>
#include <i386/setjmp.h>
#include <i386/misc_protos.h>

int	cpu_int_word[NCPUS];

extern void cpu_interrupt(int cpu);
extern int get_ncpus(void);

/*
 * Generate a clock interrupt on next running cpu
 *
 * Instead of having the master processor interrupt
 * all active processors, each processor in turn interrupts
 * the next active one. This avoids all slave processors
 * accessing the same R/W data simultaneously.
 */

void
slave_clock(void)
{
}

void
i386_signal_cpus(int event)
{
}

/*ARGSUSED*/
void
init_ast_check(
	processor_t	processor)
{
}

void
cause_ast_check(
	processor_t	processor)
{
}

/*ARGSUSED*/
kern_return_t
cpu_start(
	int	slot_num)
{
	printf("cpu_start not implemented\n");
	return (KERN_FAILURE);
}


int real_ncpus;
int wncpu = -1;

/*
 * Find out how many cpus will run
 */
 
void
mp_probe_cpus(void)
{
	int i;

	/* 
	 * get real number of cpus
	 */

	real_ncpus = get_ncpus();

	if (wncpu <= 0)
		wncpu = NCPUS;

	/*
	 * Ignore real number of cpus it if number of requested cpus
	 * is smaller.
	 * Keep it if number of requested cpu is null or larger.
	 */

	if (real_ncpus < wncpu)
		wncpu = real_ncpus;
#if	MP_V1_1
    {
	extern void validate_cpus(int);

	/*
	 * We do NOT have CPUS numbered contiguously.
	 */
	
	validate_cpus(wncpu);
    }
#else
	for (i=0; i < wncpu; i++)
		machine_slot[i].is_cpu = TRUE;
#endif
}

/*
 * invoke kdb on slave processors 
 */

void
remote_kdb(void)
{
}

/*
 * Clear kdb interrupt
 */

void
clear_kdb_intr(void)
{
}
#else /* NCPUS > 1 */
int	cpu_int_word[NCPUS];
#endif /* NCPUS > 1 */
