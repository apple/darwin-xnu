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

#include <debug.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <db_machine_commands.h>
#include <cpus.h>

#include <kern/thread.h>
#include <machine/pmap.h>
#include <machine/mach_param.h>
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
#include <ppc/setjmp.h>
#include <ppc/exception.h>

#include <kern/clock.h>
#include <kern/debug.h>
#include <machine/trap.h>
#include <kern/spl.h>
#include <pexpert/pexpert.h>
#include <ppc/mp.h>

#include <IOKit/IOPlatformExpert.h>

#include <mach/vm_prot.h>
#include <vm/pmap.h>
#include <mach/time_value.h>
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

decl_simple_lock_data(, debugger_lock)	/* debugger lock */
decl_simple_lock_data(, pbtlock)		/* backtrace print lock */

int			debugger_cpu = -1;			/* current cpu running debugger	*/
int			debugger_debug = 0;			/* Debug debugger */
int			debugger_is_slave[NCPUS];	/* Show that we were entered via sigp */
int			debugger_active[NCPUS];		/* Debugger active on CPU */
int			debugger_pending[NCPUS];	/* Debugger entry pending on CPU (this is a HACK) */
int			debugger_holdoff[NCPUS];	/* Holdoff debugger entry on this CPU (this is a HACK) */
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
void dump_backtrace(unsigned int stackptr, unsigned int fence);
void dump_savearea(savearea *sv, unsigned int fence);

#if !MACH_KDB
boolean_t	db_breakpoints_inserted = TRUE;
jmp_buf_t *db_recover = 0;
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

boolean_t db_im_stepping = 0xFFFFFFFF;	/* Remember if we were stepping */


char *failNames[] = {	

	"Debugging trap",			/* failDebug */
	"Corrupt stack",			/* failStack */
	"Corrupt mapping tables",	/* failMapping */
	"Corrupt context",			/* failContext */
	"Unknown failure code"			/* Unknown failure code - must always be last */
};

char *invxcption = "Unknown code";

extern const char version[];
extern char *trap_type[];
extern vm_offset_t mem_actual;

#if !MACH_KDB
void kdb_trap(int type, struct ppc_saved_state *regs);
void kdb_trap(int type, struct ppc_saved_state *regs) {
	return;
}
#endif

#if !MACH_KDP
void kdp_trap(int type, struct ppc_saved_state *regs);
void kdp_trap(int type, struct ppc_saved_state *regs) {
	return;
}
#endif

void
machine_startup(boot_args *args)
{
	int	boot_arg;

	if (PE_parse_boot_arg("cpus", &wncpu)) {
		if (!((wncpu > 0) && (wncpu < NCPUS)))
                        wncpu = NCPUS;
	} else 
		wncpu = NCPUS;

	if( PE_get_hotkey( kPEControlKey ))
            halt_in_debugger = halt_in_debugger ? 0 : 1;

	if (PE_parse_boot_arg("debug", &boot_arg)) {
		if (boot_arg & DB_HALT) halt_in_debugger=1;
		if (boot_arg & DB_PRT) disableDebugOuput=FALSE; 
		if (boot_arg & DB_SLOG) systemLogDiags=TRUE; 
	}

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
	if (PE_parse_boot_arg("preempt", &boot_arg)) {
		extern int default_preemption_rate;

		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_arg("kpreempt", &boot_arg)) {
		extern int kernel_preemption_mode;
		extern boolean_t zone_gc_allowed;

		kernel_preemption_mode = boot_arg;
		zone_gc_allowed = FALSE; /* XXX: TO BE REMOVED  */
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

	ml_thrm_init();							/* Start thermal monitoring on this processor */

	/*
	 * Start the system.
	 */
	setup_main();

	/* Should never return */
}

char *
machine_boot_info(
	char *buf, 
	vm_size_t size)
{
	return(PE_boot_args());
}

void
machine_conf(void)
{
	machine_info.max_cpus = NCPUS;
	machine_info.avail_cpus = 1;
	machine_info.memory_size = mem_size;
}

void
machine_init(void)
{
	clock_config();
}

void slave_machine_init(void)
{
	(void) ml_set_interrupts_enabled(FALSE);	/* Make sure we are disabled */
	clock_init();				/* Init the clock */
	cpu_machine_init();			/* Initialize the processor */
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
void machine_callstack(
	natural_t	*buf,
	vm_size_t	callstack_max)
{
}
#endif	/* MACH_ASSERT */


void
print_backtrace(struct ppc_saved_state *ssp)
{
	unsigned int stackptr, *raddr, *rstack, trans, fence;
	int i, frames_cnt, skip_top_frames, frames_max;
	unsigned int store[8];			/* Buffer for real storage reads */
	vm_offset_t backtrace_entries[32];
	thread_act_t *act;
	savearea *sv, *svssp;
	int cpu;

/*
 *	We need this lock to make sure we don't hang up when we double panic on an MP.
 */

	cpu  = cpu_number();					/* Just who are we anyways? */
	if(pbtcpu != cpu) {						/* Allow recursion */
		hw_atomic_add(&pbtcnt, 1);			/* Remember we are trying */
		while(!hw_lock_try(&pbtlock));		/* Spin here until we can get in. If we never do, well, we're crashing anyhow... */	
		pbtcpu = cpu;						/* Mark it as us */	
	}	

	svssp = (savearea *)ssp;				/* Make this easier */
	sv = 0;
	if(current_thread()) sv = (savearea *)current_act()->mact.pcb;	/* Find most current savearea if system has started */

	fence = 0xFFFFFFFF;						/* Show we go all the way */
	if(sv) fence = sv->save_r1;				/* Stop at previous exception point */
	
	if(!svssp) {							/* Should we start from stack? */
		printf("Latest stack backtrace for cpu %d:\n", cpu_number());
		__asm__ volatile("mr %0,r1" : "=r" (stackptr));	/* Get current stack */
		dump_backtrace(stackptr, fence);	/* Dump the backtrace */
		if(!sv) {							/* Leave if no saveareas */
			printf("\nKernel version:\n%s\n",version);	/* Print kernel version */
			hw_lock_unlock(&pbtlock);		/* Allow another back trace to happen */
			return;	
		}
	}
	else {									/* Were we passed an exception? */
		fence = 0xFFFFFFFF;					/* Show we go all the way */
		if(svssp->save_prev) fence = svssp->save_prev->save_r1;		/* Stop at previous exception point */
	
		printf("Latest crash info for cpu %d:\n", cpu_number());
		printf("   Exception state (sv=0x%08x)\n", sv);
		dump_savearea(svssp, fence);		/* Dump this savearea */	
	}

	if(!sv) {								/* Leave if no saveareas */
		printf("\nKernel version:\n%s\n",version);	/* Print kernel version */
		hw_lock_unlock(&pbtlock);			/* Allow another back trace to happen */
		return;	
	}
	
	printf("Proceeding back via exception chain:\n");

	while(sv) {								/* Do them all... */
		printf("   Exception state (sv=0x%08x)\n", sv);
		if(sv == svssp) {					/* Did we dump it already? */
			printf("      previously dumped as \"Latest\" state. skipping...\n");
		}
		else {
			fence = 0xFFFFFFFF;				/* Show we go all the way */
			if(sv->save_prev) fence = sv->save_prev->save_r1;	/* Stop at previous exception point */
			dump_savearea(sv, fence);		/* Dump this savearea */	
		}	
		
		sv = sv->save_prev;					/* Back chain */
	}
	
	printf("\nKernel version:\n%s\n",version);	/* Print kernel version */

	pbtcpu = -1;							/* Mark as unowned */
	hw_lock_unlock(&pbtlock);				/* Allow another back trace to happen */
	hw_atomic_sub(&pbtcnt, 1);				/* Show we are done */

	while(pbtcnt);							/* Wait for completion */

	return;
}

void dump_savearea(savearea *sv, unsigned int fence) {

	char *xcode;
	
	if(sv->save_exception > T_MAX) xcode = invxcption;	/* Too big for table */
	else xcode = trap_type[sv->save_exception / 4];		/* Point to the type */
	
	printf("      PC=0x%08X; MSR=0x%08x; DAR=0x%08x; DSISR=0x%08x; LR=0x%08x; R1=0x%08x; XCP=0x%08x (%s)\n",
		sv->save_srr0, sv->save_srr1, sv->save_dar, sv->save_dsisr,
		sv->save_lr, sv->save_r1, sv->save_exception, xcode);
	
	if(!(sv->save_srr1 & MASK(MSR_PR))) {		/* Are we in the kernel? */
		dump_backtrace(sv->save_r1, fence);		/* Dump the stack back trace from  here if not user state */
	}
	
	return;
}



#define DUMPFRAMES 32
#define LRindex 2

void dump_backtrace(unsigned int stackptr, unsigned int fence) {

	unsigned int bframes[DUMPFRAMES];
	unsigned int  sframe[8], raddr, dumbo;
	int i;
	
	printf("      Backtrace:\n");
	for(i = 0; i < DUMPFRAMES; i++) {			/* Dump up to max frames */
	
		if(!stackptr || (stackptr == fence)) break;		/* Hit stop point or end... */
		
		if(stackptr & 0x0000000f) {				/* Is stack pointer valid? */
			printf("\n         backtrace terminated - unaligned frame address: 0x%08x\n", stackptr);	/* No, tell 'em */
			break;
		}

		raddr = (unsigned int)LRA(PPC_SID_KERNEL, (void *)stackptr);	/* Get physical frame address */
		if(!raddr) {							/* Is it mapped? */
			printf("\n         backtrace terminated - frame not mapped: 0x%08x\n", stackptr);	/* No, tell 'em */
			break;
		}
	
		if(raddr >= mem_actual) {				/* Is it within physical RAM? */
			printf("\n         backtrace terminated - frame outside of RAM: v=0x%08x, p=%08X\n", stackptr, raddr);	/* No, tell 'em */
			break;
		}
	
		ReadReal(raddr, &sframe[0]);			/* Fetch the stack frame */

		bframes[i] = sframe[LRindex];			/* Save the link register */
		
		if(!i) printf("         ");				/* Indent first time */
		else if(!(i & 7)) printf("\n         ");	/* Skip to new line every 8 */
		printf("0x%08x ", bframes[i]);			/* Dump the link register */
		
		stackptr = sframe[0];					/* Chain back */
	}
	printf("\n");
	if(i >= DUMPFRAMES) printf("      backtrace continues...\n");	/* Say we terminated early */
	if(i) kmod_dump((vm_offset_t *)&bframes[0], i);	/* Show what kmods are in trace */
	
}
	


void 
Debugger(const char	*message) {

	int i;
	unsigned int store[8];
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
	
	if (debug_mode && debugger_active[cpu_number()]) {	/* Are we already on debugger on this processor? */
		splx(spl);
		return;										/* Yeah, don't do it again... */
	}

	if ((current_debugger != NO_CUR_DB)) {			/* If there is a debugger configured, enter it */
		printf("Debugger(%s)\n", message);
		TRAP_DEBUGGER;
		splx(spl);
		return;										/* Done debugging for a while */
	}

	printf("\nNo debugger configured - dumping debug information\n");
	mfdbatu(store[0],0);
	mfdbatl(store[1],0);	
	mfdbatu(store[2],1);					
	mfdbatl(store[3],1);					
	mfdbatu(store[4],2);				
	mfdbatl(store[5],2);					
	mfdbatu(store[6],3);				
	mfdbatl(store[7],3);					
	printf("DBAT0: %08X %08X\n", store[0], store[1]);
	printf("DBAT1: %08X %08X\n", store[2], store[3]);
	printf("DBAT2: %08X %08X\n", store[4], store[5]);
	printf("DBAT3: %08X %08X\n", store[6], store[7]);
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

void SysChoked(int type, savearea *sv) {			/* The system is bad dead */

	unsigned int failcode;
	
	mp_disable_preemption();
	disableDebugOuput = FALSE;
	debug_mode = TRUE;

	failcode = sv->save_r3;							/* Get the failure code */
	if(failcode > failUnknown) failcode = failUnknown;	/* Set unknown code code */
	
	kprintf("System Failure: cpu=%d; code=%08X (%s)\n", cpu_number(), sv->save_r3, failNames[failcode]);
	printf("System Failure: cpu=%d; code=%08X (%s)\n", cpu_number(), sv->save_r3, failNames[failcode]);

	print_backtrace((struct ppc_saved_state *)sv);	/* Attempt to print backtrace */
	Call_DebuggerC(type, sv);						/* Attempt to get into debugger */

	if ((current_debugger != NO_CUR_DB)) Call_DebuggerC(type, sv);	/* Attempt to get into debugger */

}



/*
 *	When we get here, interruptions are disabled and we are on the debugger stack
 *	Never, ever, ever, ever enable interruptions from here on
 */

int Call_DebuggerC(
        int	type,
        struct ppc_saved_state *saved_state)
{
	int				directcall, wait;
	vm_offset_t		instr_ptr;
	unsigned int 	instr;
	int 			my_cpu, tcpu;

	my_cpu = cpu_number();								/* Get our CPU */

#if	MACH_KDB
	if((debugger_cpu == my_cpu) && 						/* Do we already own debugger? */
	  debugger_active[my_cpu] && 						/* and are we really active? */
	  db_recover && 									/* and have we set up recovery? */
	  (current_debugger == KDB_CUR_DB)) {				/* and are we in KDB (only it handles recovery) */
		kdb_trap(type, saved_state);					/* Then reenter it... */
	}
#endif
	
	hw_atomic_add(&debug_mode, 1);						/* Indicate we are in debugger */
	debugger_active[my_cpu]++;							/* Show active on our CPU */
	lock_debugger();									/* Insure that only one CPU is in debugger */

	if(db_im_stepping == my_cpu) {						/* Are we just back from a step? */
		enable_preemption_no_check();					/* Enable preemption now */
		db_im_stepping = 0xFFFFFFFF;					/* Nobody stepping right now */
	}

	if (debugger_debug) {
#if 0
		kprintf("Call_DebuggerC(%d): %08X %08X, debact = %d\n", my_cpu, type, saved_state, debug_mode);	/* (TEST/DEBUG) */
#endif
		printf("Call_Debugger: enter - cpu %d, is_slave %d, debugger_cpu %d, pc %08X\n",
		   my_cpu, debugger_is_slave[my_cpu], debugger_cpu, saved_state->srr0);
	}
	
	if (instr_ptr = (vm_offset_t)LRA(PPC_SID_KERNEL, (void *)(saved_state->srr0))) {
		instr = ml_phys_read(instr_ptr);				/* Get the trap that caused entry */
	} 
	else instr = 0;

#if 0
	if (debugger_debug) kprintf("Call_DebuggerC(%d): instr_ptr = %08X, instr = %08X\n", my_cpu, instr_ptr, instr);	/* (TEST/DEBUG) */
#endif

	if (db_breakpoints_inserted) cpus_holding_bkpts++;	/* Bump up the holding count */
	if (debugger_cpu == -1 && !debugger_is_slave[my_cpu]) {
#if 0
		if (debugger_debug) kprintf("Call_DebuggerC(%d): lasttrace = %08X\n", my_cpu, lastTrace);	/* (TEST/DEBUG) */
#endif
		debugger_cpu = my_cpu;							/* Show that we are debugger */
		lastTrace = LLTraceSet(0);						/* Disable low-level tracing */

		for(tcpu = 0; tcpu < NCPUS; tcpu++) {			/* Stop all the other guys */
			if(tcpu == my_cpu) continue;				/* Don't diddle ourselves */
			hw_atomic_add(&debugger_sync, 1);			/* Count signal sent */
			(void)cpu_signal(tcpu, SIGPdebug, 0 ,0);	/* Tell 'em to enter debugger */
		}
		(void)hw_cpu_sync(&debugger_sync, LockTimeOut);	/* Wait for the other processors to enter debug */
		debugger_sync = 0;								/* We're done with it */
	} 
	else if (debugger_cpu != my_cpu)  goto debugger_exit;	/* We are not debugger, don't continue... */
	

	if (instr == TRAP_DIRECT_INST) {
		disableDebugOuput = FALSE;
		print_backtrace(saved_state);
	}

	switch_debugger = 0;								/* Make sure switch request is off */
	directcall = 1;										/* Assume direct call */

	if (saved_state->srr1 & MASK(SRR1_PRG_TRAP)) {		/* Trap instruction? */
		
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
		(instr == TRAP_DIRECT_INST)) saved_state->srr0 += TRAP_INST_SIZE;	/* Yes, point past trap */

	if(debugger_cpu == my_cpu) LLTraceSet(lastTrace);	/* Enable tracing on the way out if we are debugger */

	wait = FALSE;										/* Assume we are not going to wait */
	if (db_run_mode == STEP_CONTINUE) {					/* Are we going to run? */
		wait = TRUE;									/* Yeah, remember to wait for breakpoints to clear */
		debugger_cpu = -1;								/* Release other processor's debuggers */
		debugger_pending[0] = 0;						/* Release request (this is a HACK) */
		debugger_pending[1] = 0;						/* Release request (this is a HACK) */
		NMIss = 0;										/* Let NMI bounce */
	}
	
	if(db_run_mode == STEP_ONCE) {						/* Are we about to step? */
		disable_preemption();							/* Disable preemption for the step */
		db_im_stepping = my_cpu;						/* Remember that I am about to step */
	}

	if (db_breakpoints_inserted) cpus_holding_bkpts--;	/* If any breakpoints, back off count */
	if (debugger_is_slave[my_cpu]) debugger_is_slave[my_cpu]--;	/* If we were a slove, uncount us */
	if (debugger_debug)
		printf("Call_Debugger: exit - cpu %d, debugger_cpu %d, run_mode %d holds %d\n",
			  my_cpu, debugger_cpu, db_run_mode,
			  cpus_holding_bkpts);

	unlock_debugger();									/* Release the lock */
	debugger_active[my_cpu]--;							/* Say we aren't active anymore */

	if (wait) while(cpus_holding_bkpts);				/* Wait for breakpoints to clear */

	hw_atomic_sub(&debug_mode, 1);						/* Set out of debug now */

	return(1);											/* Exit debugger normally */

debugger_error:
	if(db_run_mode != STEP_ONCE) enable_preemption_no_check();	/* Enable preemption, but don't preempt here */
	hw_atomic_sub(&debug_mode, 1);						/* Set out of debug now */
	return(0);											/* Return in shame... */

}

void lock_debugger(void) {
	int		my_cpu;
	register int	i;

	my_cpu = cpu_number();								/* Get our CPU number */

	while(1) {											/* Check until we get it */

		if (debugger_cpu != -1 && debugger_cpu != my_cpu) continue;	/* Someone, not us, is debugger... */
		if (hw_lock_try(&debugger_lock)) {				/* Get the debug lock */			
			if (debugger_cpu == -1 || debugger_cpu == my_cpu) break;	/* Is it us? */
			hw_lock_unlock(&debugger_lock);				/* Not us, release lock */
		}
	} 
}

void unlock_debugger(void) {

	hw_lock_unlock(&debugger_lock);

}


