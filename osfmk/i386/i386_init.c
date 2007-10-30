/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989, 1988 Carnegie Mellon University
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

#include <platforms.h>
#include <mach_kdb.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/pms.h>
#include <kern/xpr.h>
#include <kern/cpu_data.h>
#include <kern/processor.h>
#include <console/serial_protos.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <i386/fpu.h>
#include <i386/pmap.h>
#include <i386/ipl.h>
#include <i386/misc_protos.h>
#include <i386/cpuid.h>
#include <i386/mp.h>
#include <i386/mp_desc.h>
#include <i386/machine_routines.h>
#include <i386/machine_check.h>
#include <i386/postcode.h>
#include <i386/Diagnostics.h>
#include <i386/pmCPU.h>
#include <i386/tsc.h>
#include <i386/hpet.h>
#include <i386/locks.h> /* LcksOpts */
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */
#include <ddb/tr.h>

static boot_args *kernelBootArgs;

int debug_task;

extern int disableConsoleOutput;
extern const char version[];
extern const char version_variant[];
extern int nx_enabled;

extern int noVMX;	/* if set, rosetta should not emulate altivec */

/*
 *	Cpu initialization.  Running virtual, but without MACH VM
 *	set up.  First C routine called.
 */
void
i386_init(vm_offset_t boot_args_start)
{
	unsigned int	maxmem;
	uint64_t	maxmemtouse;
	unsigned int	cpus;
	boolean_t	legacy_mode;

	postcode(I386_INIT_ENTRY);

	i386_macho_zerofill();

	/* Initialize machine-check handling */
	mca_cpu_init();

	/*
	 * Setup boot args given the physical start address.
	 */
	kernelBootArgs = (boot_args *)
		ml_static_ptovirt(boot_args_start);
        kernelBootArgs->MemoryMap = (uint32_t)
		ml_static_ptovirt((vm_offset_t)kernelBootArgs->MemoryMap);
        kernelBootArgs->deviceTreeP = (uint32_t)
		ml_static_ptovirt((vm_offset_t)kernelBootArgs->deviceTreeP);

	master_cpu = 0;
	(void) cpu_data_alloc(TRUE);
	cpu_init();
	postcode(CPU_INIT_D);

	PE_init_platform(FALSE, kernelBootArgs);
	postcode(PE_INIT_PLATFORM_D);

	printf_init();			/* Init this in case we need debugger */
	panic_init();			/* Init this in case we need debugger */

	/* setup debugging output if one has been chosen */
	PE_init_kprintf(FALSE);

	if (!PE_parse_boot_arg("diag", &dgWork.dgFlags))
		dgWork.dgFlags = 0;

	serialmode = 0;
	if(PE_parse_boot_arg("serial", &serialmode)) {
		/* We want a serial keyboard and/or console */
		kprintf("Serial mode specified: %08X\n", serialmode);
	}
	if(serialmode & 1) {
		(void)switch_to_serial_console();
		disableConsoleOutput = FALSE;	/* Allow printfs to happen */
	}

	/* setup console output */
	PE_init_printf(FALSE);

	kprintf("version_variant = %s\n", version_variant);
	kprintf("version         = %s\n", version);
	
	if (!PE_parse_boot_arg("maxmem", &maxmem))
		maxmemtouse=0;
	else
	        maxmemtouse = ((uint64_t)maxmem) * (uint64_t)(1024 * 1024);

	if (PE_parse_boot_arg("cpus", &cpus)) {
		if ((0 < cpus) && (cpus < max_ncpus))
                        max_ncpus = cpus;
	}

	/*
	 * debug support for > 4G systems
	 */
	if (!PE_parse_boot_arg("himemory_mode", &vm_himemory_mode))
	        vm_himemory_mode = 0;

	if (!PE_parse_boot_arg("immediate_NMI", &force_immediate_debugger_NMI))
		force_immediate_debugger_NMI = FALSE;

	/*
	 * At this point we check whether we are a 64-bit processor
	 * and that we're not restricted to legacy mode, 32-bit operation.
	 */
	boolean_t IA32e = FALSE;
	if (cpuid_extfeatures() & CPUID_EXTFEATURE_EM64T) {
		kprintf("EM64T supported");
		if (PE_parse_boot_arg("-legacy", &legacy_mode)) {
			kprintf(" but legacy mode forced\n");
		} else {
			IA32e = TRUE;
			kprintf(" and will be enabled\n");
		}
	}

	if (!(cpuid_extfeatures() & CPUID_EXTFEATURE_XD))
		nx_enabled = 0;

	/* Obtain "lcks" options:this currently controls lock statistics */
	if (!PE_parse_boot_arg("lcks", &LcksOpts))
		LcksOpts = 0;

	/*   
	 * VM initialization, after this we're using page tables...
	 * The maximum number of cpus must be set beforehand.
	 */
	i386_vm_init(maxmemtouse, IA32e, kernelBootArgs);

	if ( ! PE_parse_boot_arg("novmx", &noVMX))
		noVMX = 0;	/* OK to support Altivec in rosetta? */

	tsc_init();
	hpet_init();
	power_management_init();

	PE_init_platform(TRUE, kernelBootArgs);

	/* create the console for verbose or pretty mode */
	PE_create_console();

	processor_bootstrap();
	thread_bootstrap();

	machine_startup();
}
