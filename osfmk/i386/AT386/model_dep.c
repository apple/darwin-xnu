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
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/time_out.h>
#include <kern/cpu_data.h>
#include <i386/fpu.h>
#include <i386/ipl.h>
#include <i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/rtclock_entries.h>
#include <i386/mp.h>
#include <pexpert/i386/boot.h>
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */

#if	NCPUS > 1
#include <i386/mp_desc.h>
#endif	/* NCPUS */

#if	NCPUS > 1
#include <i386/mp.h>
#endif	/* NCPUS > 1 */

#include <IOKit/IOPlatformExpert.h>

static void machine_conf(void);
#include <i386/cpuid.h>

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
		extern int default_preemption_rate;

		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_arg("unsafe", &boot_arg)) {
		extern int max_unsafe_quanta;

		max_unsafe_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("poll", &boot_arg)) {
		extern int max_poll_quanta;

		max_poll_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("yield", &boot_arg)) {
		extern int sched_poll_yield_shift;

		sched_poll_yield_shift = boot_arg;
	}

	machine_conf();

#if NOTYET
	ml_thrm_init();		/* Start thermal monitoring on this processor */
#endif

	/*
	 * Start the system.
	 */
	setup_main();

	/* Should never return */
}


static void
machine_conf(void)
{
	machine_info.max_cpus = NCPUS;
	machine_info.avail_cpus = 1;
	machine_info.memory_size = mem_size;
}

/*
 * Find devices.  The system is alive.
 */
void
machine_init(void)
{
	int unit;
	const char *p;
	int n;

	/*
	 * Display CPU identification
	 */
	cpuid_cpu_display("CPU identification", 0);
	cpuid_feature_display("CPU features", 0);


#if	NCPUS > 1
	smp_init();
#endif

	/*
	 * Set up to use floating point.
	 */
	init_fpu();

	/*
	 * Configure clock devices.
	 */
	clock_config();
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
		if (!reset_mem_on_reboot)
			*(unsigned short *)phystokv(0x472) = 0x1234;

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
#include <i386/rtclock_entries.h>
extern kern_return_t	sysclk_gettime(
			mach_timespec_t	*cur_time);
void fc_get(mach_timespec_t *ts) {
	(void )sysclk_gettime(ts);
}

void
Debugger(
	const char	*message)
{
	printf("Debugger called: <%s>\n", message);

	draw_panic_dialog();

	__asm__("int3");
}

void
display_syscall(int syscall)
{
	printf("System call happened %d\n", syscall);
}

#if	XPR_DEBUG && (NCPUS == 1)

extern kern_return_t	sysclk_gettime_interrupts_disabled(
				mach_timespec_t	*cur_time);

int	xpr_time(void)
{
        mach_timespec_t	time;

	sysclk_gettime_interrupts_disabled(&time);
	return(time.tv_sec*1000000 + time.tv_nsec/1000);
}
#endif	/* XPR_DEBUG && (NCPUS == 1) */

enable_bluebox()
{
}
disable_bluebox()
{
}

char *
machine_boot_info(char *buf, vm_size_t size)
{
	*buf ='\0';
	return buf;
}

