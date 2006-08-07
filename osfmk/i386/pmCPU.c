/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/pmCPU.h>
#include <i386/cpuid.h>
#if MACH_KDB
#include <i386/db_machdep.h>
#include <ddb/db_aout.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_expr.h>
#endif

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

/*
 * Nap control variables:
 */
uint32_t napCtl = 0;			/* Defaults to neither napping
					   nor halting */
uint32_t forcenap = 0;			/* Force nap (fn) boot-arg controls */
uint32_t maxBusDelay = 0xFFFFFFFF;	/* Maximum memory bus delay that
					   I/O devices can tolerate
					   before errors (nanoseconds) */
uint32_t C4C2SnoopDelay = 0;		/* C4 to C2 transition time -
					   time before a C4 system
					   can snoop (nanoseconds) */

/*
 * We are being asked to set PState (sel).
 */
void
pmsCPUSet(uint32_t sel)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUSet != NULL)
	(*pmDispatch->pmsCPUSet)(sel);
    else
	pmInitState.PState = sel;
}

/*
 * This code configures the initial step tables.  It should be called after
 * the timebase frequency is initialized.
 *
 * Note that this is not used in normal operation.  It is strictly for
 * debugging/testing purposes.
 */
void
pmsCPUConf(void)
{

    if (pmDispatch != NULL && pmDispatch->pmsCPUConf != NULL)
	(*pmDispatch->pmsCPUConf)();
}

/*
 * Machine-dependent initialization.
 */
void
pmsCPUMachineInit(void)
{
    /*
     * Initialize some of the initial state to "uninitialized" until
     * it gets set with something more useful.  This allows the KEXT
     * to determine if the initial value was actually set to something.
     */
    pmInitState.PState = -1;
    pmInitState.PLimit = -1;

    if (pmDispatch != NULL && pmDispatch->pmsCPUMachineInit != NULL)
	(*pmDispatch->pmsCPUMachineInit)();
}

/*
 * This function should be called once for each processor to force the
 * processor to the correct initial voltage and frequency.
 */
void
pmsCPUInit(void)
{
    pmsCPUMachineInit();
    if (pmDispatch != NULL && pmDispatch->pmsCPUInit != NULL)
	(*pmDispatch->pmsCPUInit)();
}

/*
 * Broadcast a change to all processing including ourselves.
 */
void
pmsCPURun(uint32_t nstep)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPURun != NULL)
	(*pmDispatch->pmsCPURun)(nstep);
}

/*
 * Return the current state of a core.
 */
uint32_t
pmsCPUQuery(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUQuery != NULL)
	return((*pmDispatch->pmsCPUQuery)());

    /*
     * Return a non-sense value.
     */
    return((~0) << 16);
}

/*
 * Return the current state of the package.
 */
uint32_t
pmsCPUPackageQuery(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUPackageQuery != NULL)
	return((*pmDispatch->pmsCPUPackageQuery)());

    /*
     * Return a non-sense value.
     */
    return((~0) << 16);
}

/*
 * Force the CPU package to the lowest power level.  This is a low-level
 * interface meant to be called from the panic or debugger code to bring
 * the CPU to a safe power level for unmanaged operation.
 *
 * Note that while this will bring an entire package to a safe level, it
 * cannot affect other packages.  As a general rule, this should be run on
 * every code as part of entering the debugger or on the panic path.
 */
void
pmsCPUYellowFlag(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUYellowFlag != NULL)
	(*pmDispatch->pmsCPUYellowFlag)();
}

/*
 * Restore the CPU to the power state it was in before a yellow flag.
 */
void
pmsCPUGreenFlag(void)
{
    if (pmDispatch != NULL && pmDispatch->pmsCPUGreenFlag != NULL)
	(*pmDispatch->pmsCPUGreenFlag)();
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
    uint32_t	cpuModel;
    uint32_t	cpuFamily;
    uint32_t	xcpuid[4];

    /*
     * Initialize the lock for the KEXT initialization.
     */
    simple_lock_init(&pm_init_lock, 0);

    /*
     * XXX
     *
     * The following is a hack to disable power management on some systems
     * until the KEXT is done.  This is strictly temporary!!!
     */
    do_cpuid(1, xcpuid);
    cpuFamily = (xcpuid[eax] >> 8) & 0xf;
    cpuModel  = (xcpuid[eax] >> 4) & 0xf;

    if (cpuFamily != 0x6 || cpuModel < 0xe)
	pmDispatch = NULL;

    if (pmDispatch != NULL && pmDispatch->cstateInit != NULL)
	(*pmDispatch->cstateInit)();
}

/*
 * This function will update the system nap policy.  It should be called
 * whenever conditions change: when the system is ready to being napping
 * and if something changes the rules (e.g. a sysctl altering the policy
 * for debugging).
 */
void
machine_nap_policy(void)
{
    if (pmDispatch != NULL && pmDispatch->cstateNapPolicy != NULL)
	napCtl = (*pmDispatch->cstateNapPolicy)(forcenap, napCtl);
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

static inline void
sti(void) {
	__asm__ volatile ( "sti" : : : "memory");
}

/*
 * Called when the CPU is idle.  It will choose the best C state to
 * be in.
 */
void
machine_idle_cstate(void)
{
    if (pmDispatch != NULL && pmDispatch->cstateMachineIdle != NULL)
	(*pmDispatch->cstateMachineIdle)(napCtl);
    else {
	sti();
    }
}

static pmStats_t *
pmsCPUStats(void)
{
    cpu_data_t	*pp;

    pp = current_cpu_datap();
    return(&pp->cpu_pmStats);
}

static pmsd *
pmsCPUStepperData(void)
{
    cpu_data_t	*pp;

    pp = current_cpu_datap();
    return(&pp->pms);
}

static uint64_t *
CPUHPETAddr(void)
{
    cpu_data_t	*pp;
    pp = current_cpu_datap();
    return(pp->cpu_pmHpet);
}

/*
 * Called by the power management kext to register itself and to get the
 * callbacks it might need into other power management functions.
 */
void
pmRegister(pmDispatch_t *cpuFuncs, pmCallBacks_t *callbacks)
{
    if (callbacks != NULL) {
	callbacks->Park        = pmsPark;
	callbacks->Run         = pmsRun;
	callbacks->RunLocal    = pmsRunLocal;
	callbacks->SetStep     = pmsSetStep;
	callbacks->NapPolicy   = machine_nap_policy;
	callbacks->Build       = pmsBuild;
	callbacks->Stats       = pmsCPUStats;
	callbacks->StepperData = pmsCPUStepperData;
	callbacks->HPETAddr    = CPUHPETAddr;
	callbacks->InitState   = &pmInitState;
    }

    if (cpuFuncs != NULL)
	pmDispatch = cpuFuncs;
}

/*
 * Unregisters the power management functions from the kext.
 */
void
pmUnRegister(pmDispatch_t *cpuFuncs)
{
    if (cpuFuncs != NULL && pmDispatch == cpuFuncs)
	pmDispatch = NULL;
}

#if MACH_KDB
/*
 * XXX stubs for now
 */
void
db_cfg(__unused db_expr_t addr,
       __unused int have_addr,
       __unused db_expr_t count,
       __unused char *modif)
{
    return;
}

void
db_display_iokit(__unused db_expr_t addr,
		 __unused int have_addr,
		 __unused db_expr_t count,
		 __unused char *modif)
{
    return;
}

void
db_dtimers(__unused db_expr_t addr,
	   __unused int have_addr,
	   __unused db_expr_t count,
	   __unused char *modif)
{
    return;
}

void
db_intcnt(__unused db_expr_t addr,
	  __unused int have_addr,
	  __unused db_expr_t count,
	  __unused char *modif)
{
    return;
}

void
db_nap(__unused db_expr_t addr,
       __unused int have_addr,
       __unused db_expr_t count,
       __unused char *modif)
{
    return;
}

void
db_pmgr(__unused db_expr_t addr,
	__unused int have_addr,
	__unused db_expr_t count,
	__unused char *modif)
{
    return;
}

void
db_test(__unused db_expr_t addr,
	__unused int have_addr,
	__unused db_expr_t count,
	__unused char *modif)
{
    return;
}

void
db_getpmgr(__unused pmData_t *pmj)
{
}
#endif
