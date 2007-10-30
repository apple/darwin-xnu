/*
 * Copyright (c) 2004-2007 Apple Inc. All rights reserved.
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
 * CPU-specific power management support.
 *
 * Implements the "wrappers" to the KEXT.
 */
#include <i386/machine_routines.h>
#include <i386/machine_cpu.h>
#include <i386/misc_protos.h>
#include <i386/pmap.h>
#include <i386/asm.h>
#include <i386/mp.h>
#include <i386/proc_reg.h>
#include <kern/pms.h>
#include <kern/processor.h>
#include <i386/cpu_threads.h>
#include <i386/pmCPU.h>
#include <i386/cpuid.h>
#include <i386/rtclock.h>

extern int disableConsoleOutput;

decl_simple_lock_data(,pm_init_lock);

/*
 * The following is set when the KEXT loads and initializes.
 */
pmDispatch_t	*pmDispatch	= NULL;

/*
 * Current power management states (for use until KEXT is loaded).
 */
static pmInitState_t	pmInitState;

static uint32_t		pmInitDone	= 0;

/*
 * Nap control variables:
 */
uint32_t forcenap = 0;			/* Force nap (fn) boot-arg controls */

/*
 * Do any initialization needed
 */
void
pmsInit(void)
{
    static int		initialized	= 0;

    /*
     * Initialize some of the initial state to "uninitialized" until
     * it gets set with something more useful.  This allows the KEXT
     * to determine if the initial value was actually set to something.
     */
    if (!initialized) {
	pmInitState.PState = -1;
	pmInitState.PLimit = -1;
	pmInitState.maxBusDelay = -1;
	initialized = 1;
    }

    if (pmDispatch != NULL && pmDispatch->pmsInit != NULL)
	(*pmDispatch->pmsInit)();
}

/*
 * Start the power management stepper on all processors
 *
 * All processors must be parked.  This should be called when the hardware
 * is ready to step.  Probably only at boot and after wake from sleep.
 *
 */
void
pmsStart(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsStart != NULL)
	(*pmDispatch->pmsStart)();
}

/*
 * Park the stepper execution.  This will force the stepper on this
 * processor to abandon its current step and stop.  No changes to the
 * hardware state is made and any previous step is lost.
 *	
 * This is used as the initial state at startup and when the step table
 * is being changed.
 *
 */
void
pmsPark(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsPark != NULL)
	(*pmDispatch->pmsPark)();
}

/*
 * Control the Power Management Stepper.
 * Called from user state by the superuser.
 * Interrupts disabled.
 *
 * This interface is deprecated and is now a no-op.
 */
kern_return_t
pmsControl(__unused uint32_t request, __unused user_addr_t reqaddr,
	   __unused uint32_t reqsize)
{
    return(KERN_SUCCESS);
}

/*
 * Broadcast a change to all processors including ourselves.
 *
 * Interrupts disabled.
 */
void
pmsRun(uint32_t nstep)
{
    if (pmDispatch != NULL && pmDispatch->pmsRun != NULL)
	(*pmDispatch->pmsRun)(nstep);
}

/*
 * Build the tables needed for the stepper.  This includes both the step
 * definitions and the step control table.
 *
 * We most absolutely need to be parked before this happens because we're
 * going to change the table.  We also have to be complte about checking
 * for errors.  A copy is always made because we don't want to be crippled
 * by not being able to change the table or description formats.
 *
 * We pass in a table of external functions and the new stepper def uses
 * the corresponding indexes rather than actual function addresses.  This
 * is done so that a proper table can be built with the control syscall.
 * It can't supply addresses, so the index has to do.  We internalize the
 * table so our caller does not need to keep it.  Note that passing in a 0
 * will use the current function table.  Also note that entry 0 is reserved
 * and must be 0, we will check and fail the build.
 *
 * The platformData parameter is a 32-bit word of data that is passed unaltered
 * to the set function.
 *
 * The queryFunc parameter is the address of a function that will return the
 * current state of the platform. The format of the data returned is the same
 * as the platform specific portions of pmsSetCmd, i.e., pmsXClk, pmsVoltage,
 * and any part of pmsPowerID that is maintained by the platform hardware
 * (an example would be the values of the gpios that correspond to pmsPowerID).
 * The value should be constructed by querying hardware rather than returning
 * a value cached by software. One of the intents of this function is to help
 * recover lost or determine initial power states.
 *
 */
kern_return_t
pmsBuild(pmsDef *pd, uint32_t pdsize, pmsSetFunc_t *functab,
	 uint32_t platformData, pmsQueryFunc_t queryFunc)
{
    kern_return_t	rc	= 0;

    if (pmDispatch != NULL && pmDispatch->pmsBuild != NULL)
	rc = (*pmDispatch->pmsBuild)(pd, pdsize, functab,
				     platformData, queryFunc);

    return(rc);
}


/*
 * Load a new ratio/VID table.
 *
 * Note that this interface is specific to the Intel SpeedStep implementation.
 * It is expected that this will only be called once to override the default
 * ratio/VID table when the platform starts.
 *
 * Normally, the table will need to be replaced at the same time that the
 * stepper program proper is replaced, as the PState indices from an old
 * program may no longer be valid.  When replacing the default program this
 * should not be a problem as any new table will have at least two PState
 * entries and the default program only references P0 and P1.
 */
kern_return_t
pmsCPULoadVIDTable(uint16_t *tablep, int nstates)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPULoadVIDTable != NULL)
	return((*pmDispatch->pmsCPULoadVIDTable)(tablep, nstates));
    else {
	int	i;

	if (nstates > MAX_PSTATES)
	    return(KERN_FAILURE);

	for (i = 0; i < nstates; i += 1)
	    pmInitState.VIDTable[i] = tablep[i];
    }
    return(KERN_SUCCESS);
}

/*
 * Set the (global) PState limit.  CPUs will not be permitted to run at
 * a lower (more performant) PState than this.
 */
kern_return_t
pmsCPUSetPStateLimit(uint32_t limit)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUSetPStateLimit != NULL)
	return((*pmDispatch->pmsCPUSetPStateLimit)(limit));

    pmInitState.PLimit = limit;
    return(KERN_SUCCESS);
}

/*
 * Initialize the Cstate change code.
 */
void
power_management_init(void)
{
    static boolean_t	initialized	= FALSE;

    /*
     * Initialize the lock for the KEXT initialization.
     */
    if (!initialized) {
	simple_lock_init(&pm_init_lock, 0);
	initialized = TRUE;
    }

    if (pmDispatch != NULL && pmDispatch->cstateInit != NULL)
	(*pmDispatch->cstateInit)();
}

/*
 * ACPI calls the following routine to set/update mwait hints.  A table
 * (possibly null) specifies the available Cstates and their hints, all
 * other states are assumed to be invalid.  ACPI may update available
 * states to change the nap policy (for example, while AC power is
 * available).
 */
kern_return_t
Cstate_table_set(Cstate_hint_t *tablep, unsigned int nstates)
{
    if (forcenap)
	return(KERN_SUCCESS);

    if (pmDispatch != NULL && pmDispatch->cstateTableSet != NULL)
	return((*pmDispatch->cstateTableSet)(tablep, nstates));
    else {
	unsigned int	i;

	for (i = 0; i < nstates; i += 1) {
	    pmInitState.CStates[i].number = tablep[i].number;
	    pmInitState.CStates[i].hint   = tablep[i].hint;
	}

	pmInitState.CStatesCount = nstates;
    }
    return(KERN_SUCCESS);
}

/*
 * Called when the CPU is idle.  It will choose the best C state to
 * be in.
 */
void
machine_idle_cstate(boolean_t halted)
{
	if (pmInitDone
	    && pmDispatch != NULL
	    && pmDispatch->cstateMachineIdle != NULL)
		(*pmDispatch->cstateMachineIdle)(!halted ?
						 0x7FFFFFFFFFFFFFFFULL : 0ULL);
	else if (halted) {
	    /*
	     * If no power managment and a processor is taken off-line,
	     * then invalidate the cache and halt it (it will not be able
	     * to be brought back on-line without resetting the CPU).
	     */
	    __asm__ volatile ( "wbinvd; hlt" );
	} else {
	    /*
	     * If no power management, re-enable interrupts and halt.
	     * This will keep the CPU from spinning through the scheduler
	     * and will allow at least some minimal power savings (but it
	     * may cause problems in some MP configurations w.r.t to the
	     * APIC stopping during a P-State transition).
	     */
	    __asm__ volatile ( "sti; hlt" );
	}
}

/*
 * Called when the CPU is to be halted.  It will choose the best C-State
 * to be in.
 */
void
pmCPUHalt(uint32_t reason)
{

    switch (reason) {
    case PM_HALT_DEBUG:
	__asm__ volatile ("wbinvd; hlt");
	break;

    case PM_HALT_PANIC:
	__asm__ volatile ("cli; wbinvd; hlt");
	break;

    case PM_HALT_NORMAL:
    default:
	__asm__ volatile ("cli");

	if (pmInitDone
	    && pmDispatch != NULL
	    && pmDispatch->pmCPUHalt != NULL) {
	    (*pmDispatch->pmCPUHalt)();
	} else {
	    cpu_data_t	*cpup	= current_cpu_datap();

	    /*
	     * If no power managment and a processor is taken off-line,
	     * then invalidate the cache and halt it (it will not be able
	     * to be brought back on-line without resetting the CPU).
	     */
	    __asm__ volatile ("wbinvd");
	    cpup->lcpu.halted = TRUE;
	    __asm__ volatile ( "wbinvd; hlt" );
	}
	break;
    }
}

/*
 * Called to initialize the power management structures for the CPUs.
 */
void
pmCPUStateInit(void)
{
    if (pmDispatch != NULL && pmDispatch->pmCPUStateInit != NULL)
	(*pmDispatch->pmCPUStateInit)();
}

static void
pmInitComplete(void)
{
    pmInitDone = 1;
}

static x86_lcpu_t *
pmGetLogicalCPU(int cpu)
{
    return(cpu_to_lcpu(cpu));
}

static x86_lcpu_t *
pmGetMyLogicalCPU(void)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    return(&cpup->lcpu);
}

static x86_core_t *
pmGetCore(int cpu)
{
    return(cpu_to_core(cpu));
}

static x86_core_t *
pmGetMyCore(void)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    return(cpup->lcpu.core);
}

static x86_pkg_t *
pmGetPackage(int cpu)
{
    return(cpu_to_package(cpu));
}

static x86_pkg_t *
pmGetMyPackage(void)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    return(cpup->lcpu.core->package);
}

static void
pmLockCPUTopology(int lock)
{
    if (lock) {
	simple_lock(&x86_topo_lock);
    } else {
	simple_unlock(&x86_topo_lock);
    }
}

/*
 * Called to get the next deadline that has been set by the
 * power management code.
 */
uint64_t
pmCPUGetDeadline(cpu_data_t *cpu)
{
    uint64_t	deadline	= EndOfAllTime;

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->GetDeadline != NULL)
	deadline = (*pmDispatch->GetDeadline)(&cpu->lcpu);

    return(deadline);
}

/*
 * Called to determine if the supplied deadline or the power management
 * deadline is sooner.  Returns which ever one is first.
 */
uint64_t
pmCPUSetDeadline(cpu_data_t *cpu, uint64_t deadline)
{
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->SetDeadline != NULL)
	deadline = (*pmDispatch->SetDeadline)(&cpu->lcpu, deadline);

    return(deadline);
}

/*
 * Called when a power management deadline expires.
 */
void
pmCPUDeadline(cpu_data_t *cpu)
{
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->Deadline != NULL)
	(*pmDispatch->Deadline)(&cpu->lcpu);
}

/*
 * Called to get a CPU out of idle.
 */
boolean_t
pmCPUExitIdle(cpu_data_t *cpu)
{
    boolean_t		do_ipi;

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->exitIdle != NULL)
	do_ipi = (*pmDispatch->exitIdle)(&cpu->lcpu);
    else
	do_ipi = TRUE;

    return(do_ipi);
}

/*
 * Called when a CPU is being restarted after being powered off (as in S3).
 */
void
pmCPUMarkRunning(cpu_data_t *cpu)
{
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->markCPURunning != NULL)
	(*pmDispatch->markCPURunning)(&cpu->lcpu);
}

/*
 * Called from the HPET interrupt handler to perform the
 * necessary power management work.
 */
void
pmHPETInterrupt(void)
{
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->HPETInterrupt != NULL)
	(*pmDispatch->HPETInterrupt)();
}

/*
 * Called to get/set CPU power management state.
 */
int
pmCPUControl(uint32_t cmd, void *datap)
{
    int		rc	= -1;

    if (pmDispatch != NULL
	&& pmDispatch->pmCPUControl != NULL)
	rc = (*pmDispatch->pmCPUControl)(cmd, datap);

    return(rc);
}

/*
 * Set the worst-case time for the C4 to C2 transition.
 * No longer does anything.
 */
void
ml_set_maxsnoop(__unused uint32_t maxdelay)
{
}


/*
 * Get the worst-case time for the C4 to C2 transition.  Returns nanoseconds.
 */
unsigned
ml_get_maxsnoop(void)
{
    uint64_t	max_snoop	= 0;

    if (pmDispatch != NULL
	&& pmDispatch->getMaxSnoop != NULL)
	max_snoop = pmDispatch->getMaxSnoop();

    return((unsigned)(max_snoop & 0xffffffff));
}


uint32_t
ml_get_maxbusdelay(void)
{
    uint64_t	max_delay	= 0;

    if (pmDispatch != NULL
	&& pmDispatch->getMaxBusDelay != NULL)
	max_delay = pmDispatch->getMaxBusDelay();

    return((uint32_t)(max_delay & 0xffffffff));
}

/*
 * Set the maximum delay time allowed for snoop on the bus.
 *
 * Note that this value will be compared to the amount of time that it takes
 * to transition from a non-snooping power state (C4) to a snooping state (C2).
 * If maxBusDelay is less than C4C2SnoopDelay,
 * we will not enter the lowest power state.
 */
void
ml_set_maxbusdelay(uint32_t mdelay)
{
    uint64_t	maxdelay	= mdelay;

    if (pmDispatch != NULL
	&& pmDispatch->setMaxBusDelay != NULL)
	pmDispatch->setMaxBusDelay(maxdelay);
    else
	pmInitState.maxBusDelay = maxdelay;
}

/*
 * Put a CPU into "safe" mode with respect to power.
 *
 * Some systems cannot operate at a continuous "normal" speed without
 * exceeding the thermal design.  This is called per-CPU to place the
 * CPUs into a "safe" operating mode.
 */
void
pmSafeMode(x86_lcpu_t *lcpu, uint32_t flags)
{
    if (pmDispatch != NULL
	&& pmDispatch->pmCPUSafeMode != NULL)
	pmDispatch->pmCPUSafeMode(lcpu, flags);
    else {
	/*
	 * Do something reasonable if the KEXT isn't present.
	 *
	 * We only look at the PAUSE and RESUME flags.  The other flag(s)
	 * will not make any sense without the KEXT, so just ignore them.
	 *
	 * We set the halted flag in the LCPU structure to indicate
	 * that this CPU isn't to do anything.  If it's the CPU we're
	 * currently running on, then spin until the halted flag is
	 * reset.
	 */
	if (flags & PM_SAFE_FL_PAUSE) {
	    lcpu->halted = TRUE;
	    if (lcpu == x86_lcpu()) {
		while (lcpu->halted)
		    cpu_pause();
	    }
	}
	
	/*
	 * Clear the halted flag for the specified CPU, that will
	 * get it out of it's spin loop.
	 */
	if (flags & PM_SAFE_FL_RESUME) {
	    lcpu->halted = FALSE;
	}
    }
}

/*
 * Returns the root of the package tree.
 */
static x86_pkg_t *
pmGetPkgRoot(void)
{
    return(x86_pkgs);
}

static boolean_t
pmCPUGetHibernate(int cpu)
{
    return(cpu_datap(cpu)->cpu_hibernate);
}

static processor_t
pmLCPUtoProcessor(int lcpu)
{
    return(cpu_datap(lcpu)->cpu_processor);
}

/*
 * Called by the power management kext to register itself and to get the
 * callbacks it might need into other kernel functions.  This interface
 * is versioned to allow for slight mis-matches between the kext and the
 * kernel.
 */
void
pmKextRegister(uint32_t version, pmDispatch_t *cpuFuncs,
	       pmCallBacks_t *callbacks)
{
    if (callbacks != NULL && version == PM_DISPATCH_VERSION) {
	callbacks->InitState   = &pmInitState;
	callbacks->setRTCPop   = setPop;
	callbacks->resyncDeadlines = etimer_resync_deadlines;
	callbacks->initComplete= pmInitComplete;
	callbacks->GetLCPU     = pmGetLogicalCPU;
	callbacks->GetCore     = pmGetCore;
	callbacks->GetPackage  = pmGetPackage;
	callbacks->GetMyLCPU   = pmGetMyLogicalCPU;
	callbacks->GetMyCore   = pmGetMyCore;
	callbacks->GetMyPackage= pmGetMyPackage;
	callbacks->CoresPerPkg = cpuid_info()->cpuid_cores_per_package;
	callbacks->GetPkgRoot  = pmGetPkgRoot;
	callbacks->LockCPUTopology = pmLockCPUTopology;
	callbacks->GetHibernate    = pmCPUGetHibernate;
	callbacks->LCPUtoProcessor = pmLCPUtoProcessor;
    }

    if (cpuFuncs != NULL) {
	pmDispatch = cpuFuncs;
    }
}

/*
 * Unregisters the power management functions from the kext.
 */
void
pmUnRegister(pmDispatch_t *cpuFuncs)
{
    if (cpuFuncs != NULL && pmDispatch == cpuFuncs) {
	pmDispatch = NULL;
    }
}

