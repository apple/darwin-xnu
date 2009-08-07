/*
 * Copyright (c) 2004-2009 Apple Inc. All rights reserved.
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
#include <kern/machine.h>
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
#include <kern/sched_prim.h>

/*
 * Kernel parameter determining whether threads are halted unconditionally
 * in the idle state.  This is the default behavior.
 * See machine_idle() for use.
 */
int idlehalt					= 1;

extern int disableConsoleOutput;

decl_simple_lock_data(,pm_init_lock);

/*
 * The following is set when the KEXT loads and initializes.
 */
pmDispatch_t	*pmDispatch	= NULL;

static uint32_t		pmInitDone	= 0;


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
 * Called when the CPU is idle.  It calls into the power management kext
 * to determine the best way to idle the CPU.
 */
void
machine_idle(void)
{
    cpu_data_t		*my_cpu		= current_cpu_datap();

    if (my_cpu == NULL)
	goto out;

    /*
     * If idlehalt isn't set, then don't do any power management related
     * idle handling.
     */
    if (!idlehalt)
	goto out;

    my_cpu->lcpu.state = LCPU_IDLE;
    my_cpu->lcpu.flags |= X86CORE_FL_IDLE;
    DBGLOG(cpu_handle, cpu_number(), MP_IDLE);
    MARK_CPU_IDLE(cpu_number());

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->cstateMachineIdle != NULL)
	(*pmDispatch->cstateMachineIdle)(0x7FFFFFFFFFFFFFFFULL);
    else {
	/*
	 * If no power management, re-enable interrupts and halt.
	 * This will keep the CPU from spinning through the scheduler
	 * and will allow at least some minimal power savings (but it
	 * cause problems in some MP configurations w.r.t. the APIC
	 * stopping during a GV3 transition).
	 */
	__asm__ volatile ("sti; hlt");
    }

    /*
     * Mark the CPU as running again.
     */
    MARK_CPU_ACTIVE(cpu_number());
    DBGLOG(cpu_handle, cpu_number(), MP_UNIDLE);
    my_cpu->lcpu.flags &= ~(X86CORE_FL_IDLE | X86CORE_FL_WAKEUP);
    my_cpu->lcpu.state = LCPU_RUN;

    /*
     * Re-enable interrupts.
     */
  out:
    __asm__ volatile("sti");
}

/*
 * Called when the CPU is to be halted.  It will choose the best C-State
 * to be in.
 */
void
pmCPUHalt(uint32_t reason)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    switch (reason) {
    case PM_HALT_DEBUG:
	cpup->lcpu.state = LCPU_PAUSE;
	__asm__ volatile ("wbinvd; hlt");
	break;

    case PM_HALT_PANIC:
	cpup->lcpu.state = LCPU_PAUSE;
	__asm__ volatile ("cli; wbinvd; hlt");
	break;

    case PM_HALT_NORMAL:
    default:
	__asm__ volatile ("cli");

	if (pmInitDone
	    && pmDispatch != NULL
	    && pmDispatch->pmCPUHalt != NULL) {
	    /*
	     * Halt the CPU (and put it in a low power state.
	     */
	    (*pmDispatch->pmCPUHalt)();

	    /*
	     * We've exited halt, so get the the CPU schedulable again.
	     */
	    i386_init_slave_fast();

	    panic("init_slave_fast returned");
	} else {
	    /*
	     * If no power managment and a processor is taken off-line,
	     * then invalidate the cache and halt it (it will not be able
	     * to be brought back on-line without resetting the CPU).
	     */
	    __asm__ volatile ("wbinvd");
	    cpup->lcpu.state = LCPU_HALT;
	    __asm__ volatile ( "wbinvd; hlt" );

	    panic("back from Halt");
	}
	break;
    }
}

void
pmMarkAllCPUsOff(void)
{
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->markAllCPUsOff != NULL)
	(*pmDispatch->markAllCPUsOff)();
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

static x86_die_t *
pmGetDie(int cpu)
{
    return(cpu_to_die(cpu));
}

static x86_die_t *
pmGetMyDie(void)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    return(cpup->lcpu.die);
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

    return(cpup->lcpu.package);
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

    cpu->lcpu.flags |= X86CORE_FL_WAKEUP;
    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->exitIdle != NULL)
	do_ipi = (*pmDispatch->exitIdle)(&cpu->lcpu);
    else
	do_ipi = TRUE;

    if (do_ipi)
	cpu->lcpu.flags &= ~X86CORE_FL_WAKEUP;

    return(do_ipi);
}

kern_return_t
pmCPUExitHalt(int cpu)
{
    kern_return_t	rc	= KERN_INVALID_ARGUMENT;

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->exitHalt != NULL)
	rc = pmDispatch->exitHalt(cpu_to_lcpu(cpu));

    return(rc);
}

kern_return_t
pmCPUExitHaltToOff(int cpu)
{
    kern_return_t	rc	= KERN_INVALID_ARGUMENT;

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->exitHaltToOff != NULL)
	rc = pmDispatch->exitHaltToOff(cpu_to_lcpu(cpu));

    return(rc);
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

/*
 * Called when a CPU is being restarted after being powered off (as in S3).
 */
void
pmCPUMarkRunning(cpu_data_t *cpu)
{
    cpu_data_t	*cpup	= current_cpu_datap();

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->markCPURunning != NULL)
	(*pmDispatch->markCPURunning)(&cpu->lcpu);
    else
	cpup->lcpu.state = LCPU_RUN;
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
 * Called to save the timer state used by power management prior
 * to "sleeping".
 */
void
pmTimerSave(void)
{
    if (pmDispatch != NULL
	&& pmDispatch->pmTimerStateSave != NULL)
	(*pmDispatch->pmTimerStateSave)();
}

/*
 * Called to restore the timer state used by power management after
 * waking from "sleep".
 */
void
pmTimerRestore(void)
{
    if (pmDispatch != NULL
	&& pmDispatch->pmTimerStateRestore != NULL)
	(*pmDispatch->pmTimerStateRestore)();
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
}

uint64_t
ml_get_maxintdelay(void)
{
    uint64_t	max_delay	= 0;

    if (pmDispatch != NULL
	&& pmDispatch->getMaxIntDelay != NULL)
	max_delay = pmDispatch->getMaxIntDelay();

    return(max_delay);
}

/*
 * Set the maximum delay allowed for an interrupt.
 */
void
ml_set_maxintdelay(uint64_t mdelay)
{
    if (pmDispatch != NULL
	&& pmDispatch->setMaxIntDelay != NULL)
	pmDispatch->setMaxIntDelay(mdelay);
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
	 * We set the CPU's state to indicate that it's halted.  If this
	 * is the CPU we're currently running on, then spin until the
	 * state becomes non-halted.
	 */
	if (flags & PM_SAFE_FL_PAUSE) {
	    lcpu->state = LCPU_PAUSE;
	    if (lcpu == x86_lcpu()) {
		while (lcpu->state == LCPU_PAUSE)
		    cpu_pause();
	    }
	}
	
	/*
	 * Clear the halted flag for the specified CPU, that will
	 * get it out of it's spin loop.
	 */
	if (flags & PM_SAFE_FL_RESUME) {
	    lcpu->state = LCPU_RUN;
	}
    }
}

static uint32_t		saved_run_count = 0;

void
machine_run_count(uint32_t count)
{
    if (pmDispatch != NULL
	&& pmDispatch->pmSetRunCount != NULL)
	pmDispatch->pmSetRunCount(count);
    else
	saved_run_count = count;
}

boolean_t
machine_cpu_is_inactive(int cpu)
{
    if (pmDispatch != NULL
	&& pmDispatch->pmIsCPUUnAvailable != NULL)
	return(pmDispatch->pmIsCPUUnAvailable(cpu_to_lcpu(cpu)));
    else
	return(FALSE);
}

static uint32_t
pmGetSavedRunCount(void)
{
    return(saved_run_count);
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

static void
pmReSyncDeadlines(int cpu)
{
    static boolean_t	registered	= FALSE;

    if (!registered) {
	PM_interrupt_register(&etimer_resync_deadlines);
	registered = TRUE;
    }

    if ((uint32_t)cpu == current_cpu_datap()->lcpu.cpu_num)
	etimer_resync_deadlines();
    else
	cpu_PM_interrupt(cpu);
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
	callbacks->setRTCPop            = setPop;
	callbacks->resyncDeadlines      = pmReSyncDeadlines;
	callbacks->initComplete         = pmInitComplete;
	callbacks->GetLCPU              = pmGetLogicalCPU;
	callbacks->GetCore              = pmGetCore;
	callbacks->GetDie               = pmGetDie;
	callbacks->GetPackage           = pmGetPackage;
	callbacks->GetMyLCPU            = pmGetMyLogicalCPU;
	callbacks->GetMyCore            = pmGetMyCore;
	callbacks->GetMyDie             = pmGetMyDie;
	callbacks->GetMyPackage         = pmGetMyPackage;
	callbacks->GetPkgRoot           = pmGetPkgRoot;
	callbacks->LockCPUTopology      = pmLockCPUTopology;
	callbacks->GetHibernate         = pmCPUGetHibernate;
	callbacks->LCPUtoProcessor      = pmLCPUtoProcessor;
	callbacks->ThreadBind           = thread_bind;
	callbacks->GetSavedRunCount     = pmGetSavedRunCount;
	callbacks->topoParms            = &topoParms;
    } else {
	panic("Version mis-match between Kernel and CPU PM");
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

/******************************************************************************
 *
 * All of the following are deprecated interfaces and no longer used.
 *
 ******************************************************************************/
kern_return_t
pmsControl(__unused uint32_t request, __unused user_addr_t reqaddr,
	   __unused uint32_t reqsize)
{
    return(KERN_SUCCESS);
}

void
pmsInit(void)
{
}

void
pmsStart(void)
{
}

void
pmsPark(void)
{
}

void
pmsRun(__unused uint32_t nstep)
{
}

kern_return_t
pmsBuild(__unused pmsDef *pd, __unused uint32_t pdsize,
	 __unused pmsSetFunc_t *functab,
	 __unused uint32_t platformData, __unused pmsQueryFunc_t queryFunc)
{
    return(KERN_SUCCESS);
}
