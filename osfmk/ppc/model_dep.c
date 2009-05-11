/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *  (c) Copyright 1988 HEWLETT-PACKARD COMPANY
 *
 *  To anyone who acknowledges that this file is provided "AS IS"
 *  without any express or implied warranty:
 *      permission to use, copy, modify, and distribute this file
 *  for any purpose is hereby granted without fee, provided that
 *  the above copyright notice and this notice appears in all
 *  copies, and that the name of Hewlett-Packard Company not be
 *  used in advertising or publicity pertaining to distribution
 *  of the software without specific, written prior permission.
 *  Hewlett-Packard Company makes no representations about the
 *  suitability of this software for any purpose.
 */
/*
 * Copyright (c) 1990,1991,1992,1994 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * THE UNIVERSITY OF UTAH AND CSL PROVIDE THIS SOFTWARE IN ITS "AS IS"
 * CONDITION, AND DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM ITS USE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 * 	Utah $Hdr: model_dep.c 1.34 94/12/14$
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <debug.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <db_machine_commands.h>

#include <kern/thread.h>
#include <machine/pmap.h>
#include <device/device_types.h>

#include <mach/vm_param.h>
#include <mach/clock_types.h>
#include <mach/machine.h>
#include <mach/kmod.h>
#include <ppc/boot.h>

#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/thread.h>
#include <ppc/asm.h>
#include <ppc/mem.h>
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#include <ppc/mappings.h>
#include <ppc/FirmwareCalls.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/hw_perfmon.h>
#include <ppc/lowglobals.h>
#include <ppc/machine_cpu.h>
#include <ppc/db_machdep.h>

#include <kern/clock.h>
#include <kern/debug.h>
#include <machine/trap.h>
#include <kern/spl.h>
#include <pexpert/pexpert.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/machine.h>
#include <vm/vm_map.h>

#include <IOKit/IOPlatformExpert.h>

#include <mach/vm_prot.h>
#include <vm/pmap.h>
#include <mach/time_value.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <machine/machparam.h>	/* for btop */

#if	MACH_KDB
#include <ddb/db_aout.h>
#include <ddb/db_output.h>
#include <ddb/db_command.h>
#include <machine/db_machdep.h>

extern struct db_command ppc_db_commands[];
#endif	/* MACH_KDB */

char kernel_args_buf[256] = "/mach_kernel";
char boot_args_buf[256] = "/mach_servers/bootstrap";
char env_buf[256];

#define TRAP_DEBUGGER	__asm__ volatile("tw 4,r3,r3");
#define TRAP_DEBUGGER_INST	0x7c831808
#define TRAP_DIRECT	__asm__ volatile("tw 4,r4,r4");
#define TRAP_DIRECT_INST	0x7c842008
#define TRAP_INST_SIZE	4
#define BREAK_TO_KDP0 0x7fe00008
#define BREAK_TO_KDP1 0x7c800008
#define BREAK_TO_KDB0 0x7c810808

/*
 * Code used to synchronize debuggers among all cpus, one active at a time, switch
 * from on to another using kdb_on! #cpu or cpu #cpu
 */

hw_lock_data_t debugger_lock;	/* debugger lock */
hw_lock_data_t pbtlock;		/* backtrace print lock */

unsigned int debugger_cpu = (unsigned)-1; /* current cpu running debugger	*/
int			debugger_debug = 0;			/* Debug debugger */
int 		db_run_mode;				/* Debugger run mode */
unsigned int debugger_sync = 0;			/* Cross processor debugger entry sync */
extern 		unsigned int NMIss;			/* NMI debounce switch */

extern volatile int panicwait;
volatile unsigned int pbtcnt = 0;
volatile unsigned int pbtcpu = -1;

unsigned int lastTrace;					/* Value of low-level exception trace controls */


volatile unsigned int	cpus_holding_bkpts;	/* counter for number of cpus holding
											   breakpoints (ie: cpus that did not
											   insert back breakpoints) */
void unlock_debugger(void);
void lock_debugger(void);
void dump_backtrace(struct savearea *sv,
		    unsigned int stackptr,
		    unsigned int fence);
void dump_savearea(struct savearea *sv,
		   unsigned int fence);

#if !MACH_KDB
boolean_t	db_breakpoints_inserted = TRUE;
jmp_buf_t *db_recover;
#endif

#if	MACH_KDB
#include <ddb/db_run.h>
int	kdb_flag=0;
extern boolean_t db_breakpoints_inserted;
extern jmp_buf_t *db_recover;
#define	KDB_READY	0x1
#endif

#if	MACH_KDP
extern int 	kdp_flag;
#define	KDP_READY	0x1
#endif

unsigned int db_im_stepping = 0xFFFFFFFF; /* Remember if we were stepping */


const char *failNames[] = {	
	"Debugging trap",			/* failDebug */
	"Corrupt stack",			/* failStack */
	"Corrupt mapping tables",	/* failMapping */
	"Corrupt context",			/* failContext */
	"No saveareas",				/* failNoSavearea */
	"Savearea corruption",		/* failSaveareaCorr */
	"Invalid live context",		/* failBadLiveContext */
	"Corrupt skip lists",		/* failSkipLists */
	"Unaligned stack",			/* failUnalignedStk */
	"Invalid pmap",				/* failPmap */
	"Lock timeout",				/* failTimeout */
	"Unknown failure code"		/* Unknown failure code - must always be last */
};

const char *invxcption = "Unknown code";

static unsigned	commit_paniclog_to_nvram;

#if !MACH_KDB
void kdb_trap(__unused int type, __unused struct savearea *regs) {}
#endif /* !MACH_KDB */

#if !MACH_KDP
void kdp_trap(__unused int type, __unused struct savearea *regs) {}
#endif /* !MACH_KDP */

extern int default_preemption_rate;
extern int max_unsafe_quanta;
extern int max_poll_quanta;

void
machine_startup(void)
{
	int	boot_arg;
	unsigned int wncpu;

	if (PE_parse_boot_argn("cpus", &wncpu, sizeof (wncpu))) {
		if ((wncpu > 0) && (wncpu < MAX_CPUS))
                        max_ncpus = wncpu;
	}

	if( PE_get_hotkey( kPEControlKey ))
            halt_in_debugger = halt_in_debugger ? 0 : 1;

	if (PE_parse_boot_argn("debug", &boot_arg, sizeof (boot_arg))) {
		if (boot_arg & DB_HALT) halt_in_debugger=1;
		if (boot_arg & DB_PRT) disable_debug_output=FALSE; 
		if (boot_arg & DB_SLOG) systemLogDiags=TRUE; 
		if (boot_arg & DB_NMI) panicDebugging=TRUE; 
		if (boot_arg & DB_LOG_PI_SCRN) logPanicDataToScreen=TRUE; 
	}
	
	if (!PE_parse_boot_argn("nvram_paniclog", &commit_paniclog_to_nvram, sizeof (commit_paniclog_to_nvram)))
		commit_paniclog_to_nvram = 1;

	PE_parse_boot_argn("vmmforce", &lowGlo.lgVMMforcedFeats, sizeof (lowGlo.lgVMMforcedFeats));

	hw_lock_init(&debugger_lock);				/* initialize debugger lock */
	hw_lock_init(&pbtlock);						/* initialize print backtrace lock */

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
	if (PE_parse_boot_argn("preempt", &boot_arg, sizeof (boot_arg))) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_argn("unsafe", &boot_arg, sizeof (boot_arg))) {
		max_unsafe_quanta = boot_arg;
	}
	if (PE_parse_boot_argn("poll", &boot_arg, sizeof (boot_arg))) {
		max_poll_quanta = boot_arg;
	}
	if (PE_parse_boot_argn("yield", &boot_arg, sizeof (boot_arg))) {
		sched_poll_yield_shift = boot_arg;
	}

	machine_conf();

	/*
	 * Kick off the kernel bootstrap.
	 */
	kernel_bootstrap();
	/*NOTREACHED*/
}

char *
machine_boot_info(__unused char *buf, __unused vm_size_t size)
{
	return(PE_boot_args());
}

void
machine_conf(void)
{
	machine_info.memory_size = mem_size;	/* Note that this will be 2 GB for >= 2 GB machines */
}

void
machine_init(void)
{
	debug_log_init();
	clock_config();
/*	Note that we must initialize the stepper tables AFTER the clock is configured!!!!! */
	if(pmsExperimental & 1) pmsCPUConf();	/* (EXPERIMENTAL) Initialize the stepper tables */
	perfmon_init();
	return;

}

void
slave_machine_init(__unused void *param)
{
	cpu_machine_init();			/* Initialize the processor */
	clock_init();				/* Init the clock */
}                               

void
halt_all_cpus(boolean_t	reboot)
{
	if(reboot)
	{
		printf("MACH Reboot\n");
		PEHaltRestart(kPERestartCPU);
	}
	else
	{
		printf("CPU halted\n");
		PEHaltRestart(kPEHaltCPU);
	} 
	while(1);
}

void
halt_cpu(void)
{
        halt_all_cpus(FALSE);
}

#if	MACH_ASSERT
/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
void
machine_callstack(__unused natural_t *buf, __unused vm_size_t callstack_max)
{
}
#endif	/* MACH_ASSERT */

void
print_backtrace(struct savearea *ssp)
{
	unsigned int stackptr, fence;
	struct savearea *sv, *svssp, *psv;
	unsigned int cpu;

/*
 *	We need this lock to make sure we don't hang up when we double panic on an MP.
 */

	cpu  = cpu_number();					/* Just who are we anyways? */
	if(pbtcpu != cpu) {						/* Allow recursion */
		(void)hw_atomic_add(&pbtcnt, 1); /* Remember we are trying */
		while(!hw_lock_try(&pbtlock));		/* Spin here until we can get in. If we never do, well, we're crashing anyhow... */	
		pbtcpu = cpu;						/* Mark it as us */	
	}	

	svssp = (struct savearea *)ssp;				/* Make this easier */
	sv = NULL;
	if(current_thread())
		sv = (struct savearea *)current_thread()->machine.pcb;	/* Find most current savearea if system has started */

	fence = 0xFFFFFFFF;						/* Show we go all the way */
	if(sv) fence = (unsigned int)sv->save_r1;	/* Stop at previous exception point */
	
	if(!svssp) {							/* Should we start from stack? */
		kdb_printf("Latest stack backtrace for cpu %d:\n", cpu_number());
		__asm__ volatile("mr %0,r1" : "=r" (stackptr));	/* Get current stack */
		dump_backtrace((struct savearea *)0,stackptr, fence);	/* Dump the backtrace */
		if(!sv) {							/* Leave if no saveareas */
			hw_lock_unlock(&pbtlock);		/* Allow another back trace to happen */
			goto pbt_exit;
		}
	}
	else {									/* Were we passed an exception? */
		fence = 0xFFFFFFFF;					/* Show we go all the way */
		if(svssp->save_hdr.save_prev) {
			if((svssp->save_hdr.save_prev <= vm_last_addr) && ((unsigned int)pmap_find_phys(kernel_pmap, (addr64_t)svssp->save_hdr.save_prev))) {	/* Valid address? */	
				psv = (struct savearea *)((unsigned int)svssp->save_hdr.save_prev);	/* Get the 64-bit back chain converted to a regualr pointer */
				fence = (unsigned int)psv->save_r1;	/* Stop at previous exception point */
			}
		}
	
		kdb_printf("Latest crash info for cpu %d:\n", cpu_number());
		kdb_printf("   Exception state (sv=%p)\n", svssp);
		dump_savearea(svssp, fence);		/* Dump this savearea */	
	}

	if(!sv) {								/* Leave if no saveareas */
		hw_lock_unlock(&pbtlock);			/* Allow another back trace to happen */
		goto pbt_exit;
	}
	
	kdb_printf("Proceeding back via exception chain:\n");

	while(sv) {								/* Do them all... */
		if(!(((addr64_t)((uintptr_t)sv) <= vm_last_addr) && 
			(unsigned int)pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)sv)))) {	/* Valid address? */	
			kdb_printf("   Exception state (sv=%p) Not mapped or invalid. stopping...\n", sv);
			break;
		}
		
		kdb_printf("   Exception state (sv=%p)\n", sv);
		if(sv == svssp) {					/* Did we dump it already? */
			kdb_printf("      previously dumped as \"Latest\" state. skipping...\n");
		}
		else {
			fence = 0xFFFFFFFF;				/* Show we go all the way */
			if(sv->save_hdr.save_prev) {
				if((sv->save_hdr.save_prev <= vm_last_addr) && ((unsigned int)pmap_find_phys(kernel_pmap, (addr64_t)sv->save_hdr.save_prev))) {	/* Valid address? */	
					psv = (struct savearea *)((unsigned int)sv->save_hdr.save_prev);	/* Get the 64-bit back chain converted to a regualr pointer */
					fence = (unsigned int)psv->save_r1;	/* Stop at previous exception point */
				}
			}
			dump_savearea(sv, fence);		/* Dump this savearea */	
		}	
		
		sv = CAST_DOWN(struct savearea *, sv->save_hdr.save_prev);	/* Back chain */ 
	}
	

	pbtcpu = -1;							/* Mark as unowned */
	hw_lock_unlock(&pbtlock);				/* Allow another back trace to happen */
	(void)hw_atomic_sub(&pbtcnt, 1);  /* Show we are done */

	while(pbtcnt);							/* Wait for completion */
pbt_exit:
	panic_display_system_configuration();
	panic_display_zprint();
        dump_kext_info(&kdb_log);
	return;
}

void
dump_savearea(struct savearea *sv, unsigned int fence)
{
	const char *xcode;
	
	if(sv->save_exception > T_MAX)
		xcode = invxcption;	/* Too big for table */
	else
		xcode = trap_type[sv->save_exception / 4];		/* Point to the type */
	
	kdb_printf("      PC=0x%08X; MSR=0x%08X; DAR=0x%08X; DSISR=0x%08X; LR=0x%08X; R1=0x%08X; XCP=0x%08X (%s)\n",
		(unsigned int)sv->save_srr0, (unsigned int)sv->save_srr1, (unsigned int)sv->save_dar, sv->save_dsisr,
		(unsigned int)sv->save_lr, (unsigned int)sv->save_r1, sv->save_exception, xcode);
	
	if(!(sv->save_srr1 & MASK(MSR_PR))) {		/* Are we in the kernel? */
		dump_backtrace(sv, (unsigned int)sv->save_r1, fence);	/* Dump the stack back trace from  here if not user state */
	}
	
	return;
}

#define DUMPFRAMES 34
#define LRindex 2

void dump_backtrace(struct savearea *sv, unsigned int stackptr, unsigned int fence) {

	unsigned int bframes[DUMPFRAMES];
	unsigned int  sframe[8], raddr, dumbo;
	int i, index=0;
//	char syminfo[80];
	
	kdb_printf("      Backtrace:\n");
	if (sv != (struct savearea *)0) {
		bframes[0] = (unsigned int)sv->save_srr0;
		bframes[1] = (unsigned int)sv->save_lr;
		index = 2;
	}
	for(i = index; i < DUMPFRAMES; i++) {			/* Dump up to max frames */
	
		if(!stackptr || (stackptr == fence)) break;		/* Hit stop point or end... */
		
		if(stackptr & 0x0000000F) {				/* Is stack pointer valid? */
			kdb_printf("\n         backtrace terminated - unaligned frame address: 0x%08X\n", stackptr);	/* No, tell 'em */
			break;
		}

		raddr = (unsigned int)pmap_find_phys(kernel_pmap, (addr64_t)stackptr);	/* Get physical frame address */
		if(!raddr || (stackptr > vm_last_addr)) {		/* Is it mapped? */
			kdb_printf("\n         backtrace terminated - frame not mapped or invalid: 0x%08X\n", stackptr);	/* No, tell 'em */
			break;
		}
	
		if(!mapping_phys_lookup(raddr, &dumbo)) {	/* Is it within physical RAM? */
			kdb_printf("\n         backtrace terminated - frame outside of RAM: v=0x%08X, p=%08X\n", stackptr, raddr);	/* No, tell 'em */
			break;
		}
	
		ReadReal((addr64_t)((raddr << 12) | (stackptr & 4095)), &sframe[0]);	/* Fetch the stack frame */

		bframes[i] = sframe[LRindex];				/* Save the link register */
		
//		syms_formataddr((vm_offset_t)bframes[i], syminfo, sizeof (syminfo));
//		kdb_printf("        %s\n", syminfo);
		if(!i) kdb_printf("         ");				/* Indent first time */
		else if(!(i & 7)) kdb_printf("\n         ");	/* Skip to new line every 8 */
		kdb_printf("0x%08X ", bframes[i]);			/* Dump the link register */
		
		stackptr = sframe[0];						/* Chain back */
	}
	kdb_printf("\n");
	if(i >= DUMPFRAMES) kdb_printf("      backtrace continues...\n");	/* Say we terminated early */
	if(i) kmod_dump((vm_offset_t *)&bframes[0], i);	/* Show what kmods are in trace */
	
}
	
void commit_paniclog(void) {
	unsigned long pi_size = 0;

	if (debug_buf_size > 0)	{
		if (commit_paniclog_to_nvram) {
			unsigned int bufpos;
			
			/* XXX Consider using the WKdm compressor in the
			 * future, rather than just packing - would need to
			 * be co-ordinated with crashreporter, which decodes
			 * this post-restart. The compressor should be
			 * capable of in-place compression.
			 */
			bufpos = packA(debug_buf, (unsigned) (debug_buf_ptr - debug_buf), debug_buf_size);
			/* If compression was successful,
			 * use the compressed length
			 */
			pi_size = bufpos ? bufpos : (unsigned) (debug_buf_ptr - debug_buf);

			/* Truncate if the buffer is larger than a
			 * certain magic size - this really ought to
			 * be some appropriate fraction of the NVRAM
			 * image buffer, and is best done in the
			 * savePanicInfo() or PESavePanicInfo() calls
			 * This call must save data synchronously,
			 * since we can subsequently halt the system.
			 */
			kprintf("Attempting to commit panic log to NVRAM\n");
			/* N.B.: This routine (currently an IOKit wrapper that
			 * calls through to the appropriate platform NVRAM
			 * driver, must be panic context safe, i.e.
			 * acquire no locks or require kernel services.
			 * This does not appear to be the case currently
			 * on some platforms, unfortunately (the driver
			 * on command gate serialization).
			 */
			pi_size = PESavePanicInfo((unsigned char *)debug_buf,
			    ((pi_size > 2040) ? 2040 : pi_size));
			/* Uncompress in-place, to allow debuggers to examine
			 * the panic log.
			 */
			if (bufpos) 
				unpackA(debug_buf, bufpos);
		}
	}
}

void 
Debugger(const char	*message) {

	spl_t spl;
	
	spl = splhigh();								/* No interruptions from here on */
	
/*
 *	backtrace for Debugger() call  from panic() if no current debugger
 *	backtrace and return for double panic() call
 */
	if ((panicstr != (char *)0) && 
	  (((nestedpanic != 0) && (current_debugger == 1)) || (active_debugger == 0))) {
		print_backtrace(NULL);
		if (nestedpanic != 0)  {
			splx(spl);
			return;									/* Yeah, don't enter again... */
		}
	}
	
	if (debug_mode && getPerProc()->debugger_active) {	/* Are we already on debugger on this processor? */
		splx(spl);
		return;										/* Yeah, don't do it again... */
	}


/*
 * The above stuff catches the double panic case so we shouldn't have to worry about that here.
 */
	if ( panicstr != (char *)0 )
	{
		disable_preemption();
		/* Commit the panic log buffer to NVRAM, unless otherwise
		 * specified via a boot-arg.
		 */
		commit_paniclog();
		if(!panicDebugging) {
			unsigned int my_cpu, tcpu;

			my_cpu = cpu_number();
			debugger_cpu = my_cpu;

			(void)hw_atomic_add(&debug_mode, 1);
			PerProcTable[my_cpu].ppe_vaddr->debugger_active++;
			lock_debugger();

			for(tcpu = 0; tcpu < real_ncpus; tcpu++) {
				if(tcpu == my_cpu) continue;
				(void)hw_atomic_add(&debugger_sync, 1);
				(void)cpu_signal(tcpu, SIGPdebug, 0 ,0);
			}
			(void)hw_cpu_sync(&debugger_sync, LockTimeOut);
			debugger_sync = 0;
		}

		draw_panic_dialog();
		
		if(!panicDebugging) {
#if CONFIG_EMBEDDED
					PEHaltRestart(kPEPanicRestartCPU);
#else
					PEHaltRestart( kPEHangCPU );
#endif
		}

		enable_preemption();
	}

	if ((current_debugger != NO_CUR_DB)) {			/* If there is a debugger configured, enter it */
		printf("Debugger(%s)\n", message);
		TRAP_DEBUGGER;
		splx(spl);
		return;										/* Done debugging for a while */
	}

	printf("\nNo debugger configured - dumping debug information\n");
	printf("MSR=%08X\n",mfmsr());
	print_backtrace(NULL);
	splx(spl);
	return;
}

/*
 *		Here's where we attempt to get some diagnostic information dumped out
 *		when the system is really confused.  We will try to get into the 
 *		debugger as well.
 *
 *		We are here with interrupts disabled and on the debug stack.  The savearea
 *		that was passed in is NOT chained to the activation.
 *
 *		save_r3 contains the failure reason code.
 */

void
SysChoked(unsigned int type, struct savearea *sv)
{
	unsigned int failcode;
	const char * const pmsg = "System Failure: cpu=%d; code=%08X (%s)\n";
	mp_disable_preemption();
	disable_debug_output = FALSE;
	debug_mode = TRUE;

	failcode = (unsigned int)sv->save_r3;			/* Get the failure code */
	if(failcode > failUnknown) failcode = failUnknown;	/* Set unknown code code */
	
	kprintf(pmsg, cpu_number(), (unsigned int)sv->save_r3, failNames[failcode]);
	kdb_printf(pmsg, cpu_number(), (unsigned int)sv->save_r3, failNames[failcode]);

	print_backtrace(sv);							/* Attempt to print backtrace */

	/* Commit the panic log buffer to NVRAM, unless otherwise
	 * specified via a boot-arg. For certain types of panics
	 * which result in a "choke" exception, this may well
	 * be inadvisable, and setting the nvram_paniclog=0
	 * boot-arg may be useful.
	 */

	if (panicDebugging)
		commit_paniclog();

	Call_DebuggerC(type, sv);						/* Attempt to get into debugger */

	if ((current_debugger != NO_CUR_DB))
		Call_DebuggerC(type, sv);	/* Attempt to get into debugger */
	panic_plain(pmsg, cpu_number(), (unsigned int)sv->save_r3, failNames[failcode]);
}



/*
 *	When we get here, interruptions are disabled and we are on the debugger stack
 *	Never, ever, ever, ever enable interruptions from here on
 */

int
Call_DebuggerC(unsigned int type, struct savearea *saved_state)
{
	int				directcall, wait;
	addr64_t		instr_ptr = 0ULL;
	ppnum_t			instr_pp;
	unsigned int 	instr, tcpu, my_cpu;
	int 			wasdebugger;

	my_cpu = cpu_number();								/* Get our CPU */

#if	MACH_KDB
	if((debugger_cpu == my_cpu) && 						/* Do we already own debugger? */
	  PerProcTable[my_cpu].ppe_vaddr->debugger_active && 						/* and are we really active? */
	  db_recover && 									/* and have we set up recovery? */
	  (current_debugger == KDB_CUR_DB)) {				/* and are we in KDB (only it handles recovery) */
		kdb_trap(type, saved_state);					/* Then reenter it... */
	}
#endif
	
	(void)hw_atomic_add(&debug_mode, 1); /* Indicate we are in debugger */
	PerProcTable[my_cpu].ppe_vaddr->debugger_active++;	/* Show active on our CPU */
	
	lock_debugger();									/* Insure that only one CPU is in debugger */

	if(db_im_stepping == my_cpu) {						/* Are we just back from a step? */
		enable_preemption_no_check();					/* Enable preemption now */
		db_im_stepping = 0xFFFFFFFF;					/* Nobody stepping right now */
	}

	if (debugger_debug) {
#if 0
		kprintf("Call_DebuggerC(%d): %08X %08X, debact = %d\n", my_cpu, type, (uint32_t)saved_state, debug_mode);	/* (TEST/DEBUG) */
#endif
		printf("Call_Debugger: enter - cpu %d, is_slave %d, debugger_cpu %d, pc %08llX\n",
		   my_cpu, PerProcTable[my_cpu].ppe_vaddr->debugger_is_slave, debugger_cpu, saved_state->save_srr0);
	}
	
	instr_pp = (vm_offset_t)pmap_find_phys(kernel_pmap, (addr64_t)(saved_state->save_srr0));

	if (instr_pp) {
		instr_ptr = (addr64_t)(((addr64_t)instr_pp << 12) | (saved_state->save_srr0 & 0xFFF));	/* Make physical address */
		instr = ml_phys_read_64(instr_ptr);				/* Get the trap that caused entry */
	} 
	else instr = 0;

#if 0
	if (debugger_debug) kprintf("Call_DebuggerC(%d): instr_pp = %08X, instr_ptr = %016llX, instr = %08X\n", my_cpu, instr_pp, instr_ptr, instr);	/* (TEST/DEBUG) */
#endif

	if (db_breakpoints_inserted) cpus_holding_bkpts++;	/* Bump up the holding count */
	if ((debugger_cpu == (unsigned)-1) &&
		!PerProcTable[my_cpu].ppe_vaddr->debugger_is_slave) {
#if 0
		if (debugger_debug) kprintf("Call_DebuggerC(%d): lasttrace = %08X\n", my_cpu, lastTrace);	/* (TEST/DEBUG) */
#endif
		debugger_cpu = my_cpu;							/* Show that we are debugger */


		lastTrace = LLTraceSet(0);						/* Disable low-level tracing */

		for(tcpu = 0; tcpu < real_ncpus; tcpu++) {		/* Stop all the other guys */
			if(tcpu == my_cpu) continue;				/* Don't diddle ourselves */
			(void)hw_atomic_add(&debugger_sync, 1); /* Count signal sent */
			(void)cpu_signal(tcpu, SIGPdebug, 0 ,0);	/* Tell 'em to enter debugger */
		}
		(void)hw_cpu_sync(&debugger_sync, LockTimeOut);	/* Wait for the other processors to enter debug */
		debugger_sync = 0;								/* We're done with it */
	} 
	else if (debugger_cpu != my_cpu)  goto debugger_exit;	/* We are not debugger, don't continue... */
	

	if (instr == TRAP_DIRECT_INST) {
		disable_debug_output = FALSE;
		print_backtrace(saved_state);
	}

	switch_debugger = 0;								/* Make sure switch request is off */
	directcall = 1;										/* Assume direct call */

	if (saved_state->save_srr1 & MASK(SRR1_PRG_TRAP)) {	/* Trap instruction? */
		
		directcall = 0;									/* We had a trap not a direct call */

		switch (instr) {								/* Select trap type */

#if	MACH_KDP
			case BREAK_TO_KDP0:							/* Breakpoint into KDP? */
			case BREAK_TO_KDP1:							/* Breakpoint into KDP? */
				current_debugger = KDP_CUR_DB;			/* Yes, set KDP */
				kdp_trap(type, saved_state);			/* Enter it */
				break;
#endif
	
#if	MACH_KDB
			case BREAK_TO_KDB0: 						/* Breakpoint to KDB (the "good" debugger)? */
				current_debugger = KDB_CUR_DB;			/* Yes, set it */
				kdb_trap(type, saved_state);			/* Enter it */
				break;
#endif
				
			case TRAP_DEBUGGER_INST:					/* Should we enter the current debugger? */
			case TRAP_DIRECT_INST:						/* Should we enter the current debugger? */
				if (current_debugger == KDP_CUR_DB) 	/* Is current KDP? */
					kdp_trap(type, saved_state);		/* Yes, enter it */
				else if (current_debugger == KDB_CUR_DB) 	/* Is this KDB? */
					kdb_trap(type, saved_state);		/* Yes, go ahead and enter */
				else goto debugger_error;				/* No debugger active */
				break;
				
			default:									/* Unknown/bogus trap type */
				goto debugger_error;
		}
	}

	while(1) {											/* We are here to handle debugger switches */
		
		if(!directcall) {								/* Was this a direct call? */
			if(!switch_debugger) break;					/* No, then leave if no switch requested... */

/*
 *			Note: we can only switch to a debugger we have.  Ignore bogus switch requests.
 */
#if 0
			if (debugger_debug) kprintf("Call_DebuggerC(%d): switching debuggers\n", my_cpu);	/* (TEST/DEBUG) */
#endif
#if MACH_KDB
			if(current_debugger == KDP_CUR_DB) current_debugger = KDB_CUR_DB; /* Switch to KDB */
#if MACH_KDP
			else 
#endif
#endif
#if MACH_KDP
			if(current_debugger == KDB_CUR_DB) current_debugger = KDP_CUR_DB;		/* Switch to KDP */
#endif
		}
		
		switch_debugger = 0;							/* Clear request */
		directcall = 0;									/* Clear first-time direct call indication */

		switch (current_debugger) {						/* Enter correct debugger */
		
			case KDP_CUR_DB:							/* Enter KDP */
				kdp_trap(type, saved_state);
				break;
				
			case KDB_CUR_DB:							/* Enter KDB */
				kdb_trap(type, saved_state);
				break;
				
			default:									/* No debugger installed */
				goto debugger_error;
				break;
		}
	}

debugger_exit:
#if 0
	if (debugger_debug) kprintf("Call_DebuggerC(%d): exit - inst = %08X, cpu=%d(%d), run=%d\n", my_cpu, 
		instr, my_cpu, debugger_cpu, db_run_mode);	/* (TEST/DEBUG) */
#endif
	if ((instr == TRAP_DEBUGGER_INST) ||				/* Did we trap to enter debugger? */
		(instr == TRAP_DIRECT_INST)) saved_state->save_srr0 += TRAP_INST_SIZE;	/* Yes, point past trap */

	wasdebugger = 0;									/* Assume not debugger */
	if(debugger_cpu == my_cpu) {						/* Are the debugger processor? */
		wasdebugger = 1;								/* Remember that we were the debugger */
		LLTraceSet(lastTrace);							/* Enable tracing on the way out if we are debugger */
	}

	wait = FALSE;										/* Assume we are not going to wait */
	if (db_run_mode == STEP_CONTINUE) {					/* Are we going to run? */
		wait = TRUE;									/* Yeah, remember to wait for breakpoints to clear */
		debugger_cpu = -1;								/* Release other processor's debuggers */
		for(tcpu = 0; tcpu < real_ncpus; tcpu++)
			PerProcTable[tcpu].ppe_vaddr->debugger_pending = 0;	/* Release request (this is a HACK) */
		NMIss = 0;										/* Let NMI bounce */
	}
	
	if(db_run_mode == STEP_ONCE) {						/* Are we about to step? */
		disable_preemption();							/* Disable preemption for the step */
		db_im_stepping = my_cpu;						/* Remember that I am about to step */
	}

	if (db_breakpoints_inserted) cpus_holding_bkpts--;	/* If any breakpoints, back off count */
	if (PerProcTable[my_cpu].ppe_vaddr->debugger_is_slave) PerProcTable[my_cpu].ppe_vaddr->debugger_is_slave--;	/* If we were a slove, uncount us */
	if (debugger_debug)
		printf("Call_Debugger: exit - cpu %d, debugger_cpu %d, run_mode %d holds %d\n",
			  my_cpu, debugger_cpu, db_run_mode,
			  cpus_holding_bkpts);

	unlock_debugger();									/* Release the lock */
	PerProcTable[my_cpu].ppe_vaddr->debugger_active--;	/* Say we aren't active anymore */

	if (wait) while(cpus_holding_bkpts);				/* Wait for breakpoints to clear */


	(void)hw_atomic_sub(&debug_mode, 1); /* Set out of debug now */

	return(1);											/* Exit debugger normally */

debugger_error:
	if(db_run_mode != STEP_ONCE) enable_preemption_no_check();	/* Enable preemption, but don't preempt here */
	(void)hw_atomic_sub(&debug_mode, 1); /* Set out of debug now */
	return(0);											/* Return in shame... */

}

void
lock_debugger(void)
{
	unsigned int my_cpu;

	my_cpu = cpu_number();								/* Get our CPU number */

	while(1) { /* Check until we get it */
		if (debugger_cpu != (unsigned)-1 && debugger_cpu != my_cpu)
			continue;	/* Someone, not us, is debugger... */
		if (hw_lock_try(&debugger_lock)) { /* Get the debug lock */			
			if (debugger_cpu == (unsigned)-1 || debugger_cpu == my_cpu)
				break;	/* Is it us? */
			hw_lock_unlock(&debugger_lock); /* Not us, release lock */
		}
	} 
}

void unlock_debugger(void) {

	hw_lock_unlock(&debugger_lock);

}

int patchInst(task_t task, addr64_t vaddr, uint32_t inst);
int patchInst(task_t task, addr64_t vaddr, uint32_t inst)
{
	vm_map_t map;
	addr64_t paddr;
	uint32_t instr, nestingDepth;
	kern_return_t ret;
	vm_region_submap_short_info_data_64_t info;
	mach_msg_type_number_t count;
	mach_vm_address_t address;
	mach_vm_size_t sizeOfRegion;
	vm_prot_t reprotect;

	if(task == TASK_NULL) return -1;		/* Leave if task is bogus... */

	task_lock(task);						/* Make sure the task doesn't go anywhaere */
	if (!task->active) {					/* Is is alive? */
		task_unlock(task);					/* Nope, unlock */
		return -1;							/* Not a active task, fail... */
	}
	map = task->map;						/* Get his map */
	vm_map_reference_swap(map);				/* Don't let it go away */
	task_unlock(task);						/* Unleash the task */

	/* Find the memory permissions. */
	nestingDepth=999999;					/* Limit recursion */
	
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	address = (mach_vm_address_t)vaddr;
	sizeOfRegion = (mach_vm_size_t)4;

	ret = mach_vm_region_recurse(map, &address, &sizeOfRegion, &nestingDepth, (vm_region_recurse_info_t)&info, &count);
	if (ret != KERN_SUCCESS) {				/* Leave if it didn't work */
		vm_map_deallocate(map);				/* Drop reference on map */
		return (-1);			
	}

/*
 *	We need to check if there could be a problem if the dtrace probes are being removed and the code is being
 *	executed at the same time.  This sequence may leave us with no-execute turned on temporarily when we execute
 *	through it.
 */
 
	if (!(info.protection & VM_PROT_WRITE)) {
		/* Save the original protection values for restoration later */
		reprotect = info.protection;

		if (info.max_protection & VM_PROT_WRITE) {
			/* The memory is not currently writable, but can be made writable. */
			ret = mach_vm_protect(map, (mach_vm_offset_t)vaddr, (mach_vm_size_t)4, 0, reprotect | VM_PROT_WRITE);
		} 
		else {
			/*
			 * The memory is not currently writable, and cannot be made writable. We need to COW this memory.
			 *
			 * Strange, we can't just say "reprotect | VM_PROT_COPY", that fails.
			 */
			ret = mach_vm_protect(map, (mach_vm_offset_t)vaddr, (mach_vm_size_t)4, 0, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
		}

		if (ret != KERN_SUCCESS) {
			vm_map_deallocate(map);			/* Drop reference on map */
			return (-1);		
		}
		
	} 
	else {
		/* The memory was already writable. */
		reprotect = VM_PROT_NONE;
	}

	instr = inst;							/* Place instruction in local memory */
	ret = vm_map_write_user(map, &inst, (vm_map_address_t)vaddr, (vm_size_t)4);	/* Write the instruction */
	if (ret != KERN_SUCCESS) {				/* Leave if it didn't work */
	
		if (reprotect != VM_PROT_NONE) {
			ret = mach_vm_protect (map, (mach_vm_offset_t)vaddr, (mach_vm_size_t)4, 0, reprotect);
		}

		vm_map_deallocate(map);				/* Drop reference on map */
		return (-1);			
	}

	paddr = (addr64_t)pmap_find_phys(map->pmap, vaddr) << 12;	/* Find the physical address of the patched address */
	if(!paddr) {							/* Is address mapped now? */
		vm_map_deallocate(map);				/* Drop reference on map */
		return 0;							/* Leave... */
	}
	paddr = paddr | (vaddr & 4095);			/* Construct physical address */
	invalidate_icache64(paddr, 4, 1);		/* Flush out the instruction cache here */

	if (reprotect != VM_PROT_NONE) {
		ret = mach_vm_protect(map, (mach_vm_offset_t)vaddr, (mach_vm_size_t)4, 0, reprotect);
	}

	vm_map_deallocate(map);

	return (0);
}
