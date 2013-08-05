/*
 * Copyright (c) 2005-2008 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 *	Author: Bill Angell, Apple
 *	Date:	10/auht-five
 *
 *	Random diagnostics, augmented Derek Kumar 2011
 *
 *
 */


#include <kern/machine.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ipc_kobject.h>
#include <mach/vm_param.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <pexpert/pexpert.h>
#include <console/video_console.h>
#include <i386/cpu_data.h>
#include <i386/Diagnostics.h>
#include <i386/mp.h>
#include <i386/pmCPU.h>
#include <i386/tsc.h>
#include <mach/i386/syscall_sw.h>
#include <kern/kalloc.h>
#include <sys/kdebug.h>

diagWork        dgWork;
uint64_t        lastRuptClear = 0ULL;

void cpu_powerstats(void *);

typedef struct {
	uint64_t caperf;
	uint64_t cmperf;
	uint64_t ccres[3];
	uint64_t crtimes[4];
	uint64_t citimes[4];
	uint64_t crtime_total;
	uint64_t citime_total;
} core_energy_stat_t;

typedef struct {
	uint64_t pkg_cres[2][4];
	uint64_t pkg_power_unit;
	uint64_t pkg_energy;
	uint32_t ncpus;
	core_energy_stat_t cest[];
} pkg_energy_statistics_t;


int 
diagCall64(x86_saved_state_t * state)
{
	uint64_t        curpos, i, j;
	uint64_t        selector, data;
	uint64_t        currNap, durNap;
	x86_saved_state64_t	*regs;
	boolean_t 	diagflag;
	uint32_t	rval = 0;

	assert(is_saved_state64(state));
	regs = saved_state64(state);
	diagflag = ((dgWork.dgFlags & enaDiagSCs) != 0);
	selector = regs->rdi;

	switch (selector) {	/* Select the routine */
	case dgRuptStat:	/* Suck Interruption statistics */
		(void) ml_set_interrupts_enabled(TRUE);
		data = regs->rsi; /* Get the number of processors */

		if (data == 0) { /* If no location is specified for data, clear all
				  * counts
				  */
			for (i = 0; i < real_ncpus; i++) {	/* Cycle through
								 * processors */
				for (j = 0; j < 256; j++)
					cpu_data_ptr[i]->cpu_hwIntCnt[j] = 0;
			}

			lastRuptClear = mach_absolute_time();	/* Get the time of clear */
			rval = 1;	/* Normal return */
			break;
		}

		(void) copyout((char *) &real_ncpus, data, sizeof(real_ncpus));	/* Copy out number of
										 * processors */

		currNap = mach_absolute_time();	/* Get the time now */
		durNap = currNap - lastRuptClear;	/* Get the last interval
							 * duration */
		if (durNap == 0)
			durNap = 1;	/* This is a very short time, make it
					 * bigger */

		curpos = data + sizeof(real_ncpus);	/* Point to the next
							 * available spot */

		for (i = 0; i < real_ncpus; i++) {	/* Move 'em all out */
			(void) copyout((char *) &durNap, curpos, 8);	/* Copy out the time
									 * since last clear */
			(void) copyout((char *) &cpu_data_ptr[i]->cpu_hwIntCnt, curpos + 8, 256 * sizeof(uint32_t));	/* Copy out interrupt
															 * data for this
															 * processor */
			curpos = curpos + (256 * sizeof(uint32_t) + 8);	/* Point to next out put
									 * slot */
		}
		rval = 1;
		break;
	case dgPowerStat:
	{
		uint32_t c2l = 0, c2h = 0, c3l = 0, c3h = 0, c6l = 0, c6h = 0, c7l = 0, c7h = 0;
		uint32_t pkg_unit_l = 0, pkg_unit_h = 0, pkg_ecl = 0, pkg_ech = 0;

		pkg_energy_statistics_t pkes;
		core_energy_stat_t cest;

		bzero(&pkes, sizeof(pkes));
		bzero(&cest, sizeof(cest));

		rdmsr_carefully(MSR_IA32_PKG_C2_RESIDENCY, &c2l, &c2h);
		rdmsr_carefully(MSR_IA32_PKG_C3_RESIDENCY, &c3l, &c3h);
		rdmsr_carefully(MSR_IA32_PKG_C6_RESIDENCY, &c6l, &c6h);
		rdmsr_carefully(MSR_IA32_PKG_C7_RESIDENCY, &c7l, &c7h);

		pkes.pkg_cres[0][0] = ((uint64_t)c2h << 32) | c2l;
		pkes.pkg_cres[0][1] = ((uint64_t)c3h << 32) | c3l;
		pkes.pkg_cres[0][2] = ((uint64_t)c6h << 32) | c6l;
		pkes.pkg_cres[0][3] = ((uint64_t)c7h << 32) | c7l;

		rdmsr_carefully(MSR_IA32_PKG_POWER_SKU_UNIT, &pkg_unit_l, &pkg_unit_h);
		rdmsr_carefully(MSR_IA32_PKG_ENERGY_STATUS, &pkg_ecl, &pkg_ech);

		pkes.pkg_power_unit = ((uint64_t)pkg_unit_h << 32) | pkg_unit_l;
		pkes.pkg_energy = ((uint64_t)pkg_ech << 32) | pkg_ecl;

		pkes.ncpus = real_ncpus;

		(void) ml_set_interrupts_enabled(TRUE);

		copyout(&pkes, regs->rsi, sizeof(pkes));
		curpos = regs->rsi + sizeof(pkes);

		mp_cpus_call(CPUMASK_ALL, ASYNC, cpu_powerstats, NULL);
		
		for (i = 0; i < real_ncpus; i++) {
			cest.caperf = cpu_data_ptr[i]->cpu_aperf;
			cest.cmperf = cpu_data_ptr[i]->cpu_mperf;
			cest.ccres[0] = cpu_data_ptr[i]->cpu_c3res;
			cest.ccres[1] = cpu_data_ptr[i]->cpu_c6res;
			cest.ccres[2] = cpu_data_ptr[i]->cpu_c7res;

			bcopy(&cpu_data_ptr[i]->cpu_rtimes[0], &cest.crtimes[0], sizeof(cest.crtimes));
			bcopy(&cpu_data_ptr[i]->cpu_itimes[0], &cest.citimes[0], sizeof(cest.citimes));
			cest.citime_total = cpu_data_ptr[i]->cpu_itime_total;
			cest.crtime_total = cpu_data_ptr[i]->cpu_rtime_total;

			copyout(&cest, curpos, sizeof(cest));
			curpos += sizeof(cest);
		}
		rval = 1;
	}
		break;

#if	DEBUG
	case dgGzallocTest:
	{
		(void) ml_set_interrupts_enabled(TRUE);
		if (diagflag == 0)
			break;

		unsigned *ptr = (unsigned *)kalloc(1024);
		kfree(ptr, 1024);
		*ptr = 0x42;
	}
		break;
#endif

#if	defined(__x86_64__)		
	case	dgPermCheck:
	{
		(void) ml_set_interrupts_enabled(TRUE);
		if (diagflag == 0)
			break;

		rval = pmap_permissions_verify(kernel_pmap, kernel_map, 0, ~0ULL);
	}
 		break;
#endif /* __x86_64__*/

	default:		/* Handle invalid ones */
		rval = 0;	/* Return an exception */
	}

	regs->rax = rval;

	return rval;		/* Normal non-ast check return */
}

void cpu_powerstats(__unused void *arg) {
	cpu_data_t *cdp = current_cpu_datap();
	int cnum = cdp->cpu_number;
	uint32_t cl = 0, ch = 0, mpl = 0, mph = 0, apl = 0, aph = 0;

	rdmsr_carefully(MSR_IA32_MPERF, &mpl, &mph);
	rdmsr_carefully(MSR_IA32_APERF, &apl, &aph);

	cdp->cpu_mperf = ((uint64_t)mph << 32) | mpl;
	cdp->cpu_aperf = ((uint64_t)aph << 32) | apl;

	if (cnum & 1)
		return;

	rdmsr_carefully(MSR_IA32_CORE_C3_RESIDENCY, &cl, &ch);
	cdp->cpu_c3res = ((uint64_t)ch << 32) | cl;

	rdmsr_carefully(MSR_IA32_CORE_C6_RESIDENCY, &cl, &ch);
	cdp->cpu_c6res = ((uint64_t)ch << 32) | cl;

	rdmsr_carefully(MSR_IA32_CORE_C7_RESIDENCY, &cl, &ch);
	cdp->cpu_c7res = ((uint64_t)ch << 32) | cl;
}
