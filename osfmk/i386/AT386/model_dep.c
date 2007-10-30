/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

/*
 */

/*
 *	File:	model_dep.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Copyright (C) 1986, Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Basic initialization for I386 - ISA bus machines.
 */

#include <platforms.h>
#include <mach_kdb.h>
#include <himem.h>

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
#include <kern/cpu_data.h>
#include <kern/machine.h>
#include <i386/fpu.h>
#include <i386/ipl.h>
#include <i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/mtrr.h>
#include <i386/postcode.h>
#include <pexpert/i386/boot.h>
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */

#include <i386/mp_desc.h>
#include <i386/mp.h>

#include <IOKit/IOPlatformExpert.h>

void	enable_bluebox(void);
void	disable_bluebox(void);

static void machine_conf(void);
#include <i386/cpuid.h>

extern int		default_preemption_rate;
extern int		max_unsafe_quanta;
extern int		max_poll_quanta;
extern int		idlehalt;
extern unsigned int	panic_is_inited;

void
machine_startup()
{
	int	boot_arg;

#if 0
	if( PE_get_hotkey( kPEControlKey ))
            halt_in_debugger = halt_in_debugger ? 0 : 1;
#endif

	if (PE_parse_boot_arg("debug", &boot_arg)) {
		if (boot_arg & DB_HALT) halt_in_debugger=1;
		if (boot_arg & DB_PRT) disableDebugOuput=FALSE; 
		if (boot_arg & DB_SLOG) systemLogDiags=TRUE; 
		if (boot_arg & DB_NMI) panicDebugging=TRUE; 
		if (boot_arg & DB_LOG_PI_SCRN) logPanicDataToScreen=TRUE; 
	}

#if NOTYET
	hw_lock_init(&debugger_lock);	/* initialize debugger lock */
	hw_lock_init(&pbtlock);		/* initialize print backtrace lock */
#endif

#if	MACH_KDB
	/*
	 * Initialize KDB
	 */
#if	DB_MACHINE_COMMANDS
	db_machine_commands_install(ppc_db_commands);
#endif	/* DB_MACHINE_COMMANDS */
	ddb_init();

	if (boot_arg & DB_KDB)
		current_debugger = KDB_CUR_DB;

	/*
	 * Cause a breakpoint trap to the debugger before proceeding
	 * any further if the proper option bit was specified in
	 * the boot flags.
	 */
	if (halt_in_debugger && (current_debugger == KDB_CUR_DB)) {
	        Debugger("inline call to debugger(machine_startup)");
		halt_in_debugger = 0;
		active_debugger =1;
	}
#endif /* MACH_KDB */

	if (PE_parse_boot_arg("preempt", &boot_arg)) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_arg("unsafe", &boot_arg)) {
		max_unsafe_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("poll", &boot_arg)) {
		max_poll_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("yield", &boot_arg)) {
		sched_poll_yield_shift = boot_arg;
	}
	if (PE_parse_boot_arg("idlehalt", &boot_arg)) {
		idlehalt = boot_arg;
	}

	machine_conf();

#if NOTYET
	ml_thrm_init();		/* Start thermal monitoring on this processor */
#endif

	/*
	 * Start the system.
	 */
	kernel_bootstrap();
	/*NOTREACHED*/
}


static void
machine_conf(void)
{
	machine_info.memory_size = mem_size;
}

/*
 * Find devices.  The system is alive.
 */
void
machine_init(void)
{
	/*
	 * Display CPU identification
	 */
	cpuid_cpu_display("CPU identification", 0);
	cpuid_feature_display("CPU features", 0);


	smp_init();

	/*
	 * Set up to use floating point.
	 */
	init_fpu();

	/*
	 * Configure clock devices.
	 */
	clock_config();

	/*
	 * Initialize MTRR from boot processor.
	 */
	mtrr_init();

	/*
	 * Set up PAT for boot processor.
	 */
	pat_init();

	/*
	 * Free lowmem pages
	 */
	x86_lowmem_free();
}

/*
 * Halt a cpu.
 */
void
halt_cpu(void)
{
	halt_all_cpus(FALSE);
}

int reset_mem_on_reboot = 1;

/*
 * Halt the system or reboot.
 */
void
halt_all_cpus(boolean_t reboot)
{
	if (reboot) {
		/*
		 * Tell the BIOS not to clear and test memory.
		 */
#if 0 /* XXX fixme */
		if (!reset_mem_on_reboot)
			*(unsigned short *)phystokv(0x472) = 0x1234;
#endif

		printf("MACH Reboot\n");
		PEHaltRestart( kPERestartCPU );
	} else {
		printf("CPU halted\n");
		PEHaltRestart( kPEHaltCPU );
	}
	while(1);
}

/*XXX*/
void fc_get(mach_timespec_t *ts);
#include <kern/clock.h>
extern kern_return_t	sysclk_gettime(
			mach_timespec_t	*cur_time);
void fc_get(mach_timespec_t *ts) {
	(void )sysclk_gettime(ts);
}

void
Debugger(
	const char	*message)
{

	if (!panic_is_inited) {
		postcode(PANIC_HLT);
		asm("hlt");
	}

	printf("Debugger called: <%s>\n", message);
	kprintf("Debugger called: <%s>\n", message);

	draw_panic_dialog();

	__asm__("int3");
}

void
enable_bluebox(void)
{
}
void
disable_bluebox(void)
{
}

char *
machine_boot_info(char *buf, __unused vm_size_t size)
{
	*buf ='\0';
	return buf;
}

