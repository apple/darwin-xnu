/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <platforms.h>
#include <mach_kdb.h>
#include <himem.h>
#include <fast_idle.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/etap_macros.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/time_out.h>
#include <kern/xpr.h>
#include <kern/cpu_data.h>
#include <kern/processor.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <i386/fpu.h>
#include <i386/pmap.h>
#include <i386/ipl.h>
#include <i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/cpuid.h>
#include <i386/rtclock_entries.h>
#include <i386/mp.h>
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */
#include <ddb/tr.h>
#ifdef __MACHO__
#include <mach/boot_info.h>
#include <mach/thread_status.h>

static KernelBootArgs_t *kernelBootArgs;
#endif

vm_offset_t	boot_args_start = 0;	/* pointer to kernel arguments, set in start.s */

#ifdef __MACHO__
#include	<mach-o/loader.h>
vm_offset_t     edata, etext, end;

/*
 * Called first for a mach-o kernel before paging is set up.
 * Returns the first available physical address in memory.
 */

unsigned long
i386_preinit()
{
	struct segment_command	*sgp;
	struct section		*sp;

	sgp = (struct segment_command *) getsegbyname("__DATA");
	if (sgp) {
		sp = (struct section *) firstsect(sgp);
		if (sp) {
			do {
				if (sp->flags & S_ZEROFILL)
					bzero((char *) sp->addr, sp->size);
			} while (sp = (struct section *)nextsect(sgp, sp));
		}
	}

	kernelBootArgs = (KernelBootArgs_t *) boot_args_start;
	end = round_page( kernelBootArgs->kaddr + kernelBootArgs->ksize );

	return	end;
}
#endif

extern const char version[];
extern const char version_variant[];

/*
 *	Cpu initialization.  Running virtual, but without MACH VM
 *	set up.  First C routine called, unless i386_preinit() was called first.
 */
void
i386_init(void)
{
	unsigned int	maxmem;

	cpu_init();

	/*
	 * Setup some processor related structures to satisfy funnels.
	 * Must be done before using unparallelized device drivers.
	 */
	processor_ptr[0] = &processor_array[0];
	master_cpu = 0;
	master_processor = cpu_to_processor(master_cpu);

	PE_init_platform(FALSE, kernelBootArgs);

	/*
	 * Set up initial thread so current_thread() works early on
	 */
	thread_bootstrap();

	printf_init();			/* Init this in case we need debugger */
	panic_init();			/* Init this in case we need debugger */

	/* setup debugging output if one has been chosen */
	PE_init_kprintf(FALSE);
	kprintf("kprintf initialized\n");

	/* setup console output */
	PE_init_printf(FALSE);

	kprintf("version_variant = %s\n", version_variant);
	kprintf("version         = %s\n", version);


	/*   
	 * VM initialization, after this we're using page tables...
	 * The maximum number of cpus must be set beforehand.
	 */
	if (!PE_parse_boot_arg("maxmem", &maxmem))
		maxmem=0;
	else
		maxmem = maxmem * (1024 * 1024);

	if (PE_parse_boot_arg("cpus", &wncpu)) {
		if (!((wncpu > 0) && (wncpu < NCPUS)))
                        wncpu = NCPUS;
	} else 
		wncpu = NCPUS;

	i386_vm_init(maxmem, kernelBootArgs);

	PE_init_platform(TRUE, kernelBootArgs);

	/* create the console for verbose or pretty mode */
	PE_create_console();
	
	machine_startup();

}
