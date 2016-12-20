/*
 * Copyright (c) 2004-2011 Apple Inc. All rights reserved.
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
#include <i386/asm.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/proc_reg.h>
#include <i386/pmap.h>
#include <i386/misc_protos.h>
#include <kern/machine.h>
#include <kern/pms.h>
#include <kern/processor.h>
#include <kern/timer_queue.h>
#include <i386/cpu_threads.h>
#include <i386/pmCPU.h>
#include <i386/cpuid.h>
#include <i386/rtclock_protos.h>
#include <kern/sched_prim.h>
#include <i386/lapic.h>
#include <i386/pal_routines.h>
#include <sys/kdebug.h>
#include <i386/tsc.h>

extern int disableConsoleOutput;

#define DELAY_UNSET		0xFFFFFFFFFFFFFFFFULL

uint64_t cpu_itime_bins[CPU_ITIME_BINS] = {16* NSEC_PER_USEC, 32* NSEC_PER_USEC, 64* NSEC_PER_USEC, 128* NSEC_PER_USEC, 256* NSEC_PER_USEC, 512* NSEC_PER_USEC, 1024* NSEC_PER_USEC, 2048* NSEC_PER_USEC, 4096* NSEC_PER_USEC, 8192* NSEC_PER_USEC, 16384* NSEC_PER_USEC, 32768* NSEC_PER_USEC};
uint64_t *cpu_rtime_bins = &cpu_itime_bins[0];

/*
 * The following is set when the KEXT loads and initializes.
 */
pmDispatch_t	*pmDispatch	= NULL;

uint32_t		pmInitDone		= 0;
static boolean_t	earlyTopology		= FALSE;
static uint64_t		earlyMaxBusDelay	= DELAY_UNSET;
static uint64_t		earlyMaxIntDelay	= DELAY_UNSET;

/*
 * Initialize the Cstate change code.
 */
void
power_management_init(void)
{
    if (pmDispatch != NULL && pmDispatch->cstateInit != NULL)
	(*pmDispatch->cstateInit)();
}

static inline void machine_classify_interval(uint64_t interval, uint64_t *bins, uint64_t *binvals, uint32_t nbins) {
	uint32_t i;
 	for (i = 0; i < nbins; i++) {
 		if (interval < binvals[i]) {
 			bins[i]++;
 			break;
 		}
 	}
}

uint64_t	idle_pending_timers_processed;
uint32_t	idle_entry_timer_processing_hdeadline_threshold = 5000000;

/*
 * Called when the CPU is idle.  It calls into the power management kext
 * to determine the best way to idle the CPU.
 */
void
machine_idle(void)
{
	cpu_data_t		*my_cpu		= current_cpu_datap();
	__unused uint32_t	cnum = my_cpu->cpu_number;
	uint64_t		ctime, rtime, itime;
#if CST_DEMOTION_DEBUG
	processor_t		cproc = my_cpu->cpu_processor;
	uint64_t		cwakeups = PROCESSOR_DATA(cproc, wakeups_issued_total);
#endif /* CST_DEMOTION_DEBUG */
	uint64_t esdeadline, ehdeadline;
	boolean_t do_process_pending_timers = FALSE;

	ctime = mach_absolute_time();
	esdeadline = my_cpu->rtclock_timer.queue.earliest_soft_deadline;
	ehdeadline = my_cpu->rtclock_timer.deadline;
/* Determine if pending timers exist */    
	if ((ctime >= esdeadline) && (ctime < ehdeadline) &&
	    ((ehdeadline - ctime) < idle_entry_timer_processing_hdeadline_threshold)) {
		idle_pending_timers_processed++;
		do_process_pending_timers = TRUE;
		goto machine_idle_exit;
	} else {
		TCOAL_DEBUG(0xCCCC0000, ctime, my_cpu->rtclock_timer.queue.earliest_soft_deadline, my_cpu->rtclock_timer.deadline, idle_pending_timers_processed, 0);
	}
    
	my_cpu->lcpu.state = LCPU_IDLE;
	DBGLOG(cpu_handle, cpu_number(), MP_IDLE);
	MARK_CPU_IDLE(cnum);

	rtime = ctime - my_cpu->cpu_ixtime;

	my_cpu->cpu_rtime_total += rtime;
	machine_classify_interval(rtime, &my_cpu->cpu_rtimes[0], &cpu_rtime_bins[0], CPU_RTIME_BINS);
#if CST_DEMOTION_DEBUG
	uint32_t cl = 0, ch = 0;
	uint64_t c3res, c6res, c7res;
	rdmsr_carefully(MSR_IA32_CORE_C3_RESIDENCY, &cl, &ch);
	c3res = ((uint64_t)ch << 32) | cl;
	rdmsr_carefully(MSR_IA32_CORE_C6_RESIDENCY, &cl, &ch);
	c6res = ((uint64_t)ch << 32) | cl;
	rdmsr_carefully(MSR_IA32_CORE_C7_RESIDENCY, &cl, &ch);
	c7res = ((uint64_t)ch << 32) | cl;
#endif

	if (pmInitDone) {
		/*
		 * Handle case where ml_set_maxbusdelay() or ml_set_maxintdelay()
		 * were called prior to the CPU PM kext being registered.  We do
		 * this here since we know at this point the values will be first
		 * used since idle is where the decisions using these values is made.
		 */
		if (earlyMaxBusDelay != DELAY_UNSET)
			ml_set_maxbusdelay((uint32_t)(earlyMaxBusDelay & 0xFFFFFFFF));
		if (earlyMaxIntDelay != DELAY_UNSET)
			ml_set_maxintdelay(earlyMaxIntDelay);
	}

	if (pmInitDone
	    && pmDispatch != NULL
	    && pmDispatch->MachineIdle != NULL)
		(*pmDispatch->MachineIdle)(0x7FFFFFFFFFFFFFFFULL);
	else {
		/*
		 * If no power management, re-enable interrupts and halt.
		 * This will keep the CPU from spinning through the scheduler
		 * and will allow at least some minimal power savings (but it
		 * cause problems in some MP configurations w.r.t. the APIC
		 * stopping during a GV3 transition).
		 */
		pal_hlt();
		/* Once woken, re-disable interrupts. */
		pal_cli();
	}

	/*
	 * Mark the CPU as running again.
	 */
	MARK_CPU_ACTIVE(cnum);
	DBGLOG(cpu_handle, cnum, MP_UNIDLE);
	my_cpu->lcpu.state = LCPU_RUN;
	uint64_t ixtime = my_cpu->cpu_ixtime = mach_absolute_time();
	itime = ixtime - ctime;
	my_cpu->cpu_idle_exits++;
        my_cpu->cpu_itime_total += itime;
    	machine_classify_interval(itime, &my_cpu->cpu_itimes[0], &cpu_itime_bins[0], CPU_ITIME_BINS);
#if CST_DEMOTION_DEBUG
	cl = ch = 0;
	rdmsr_carefully(MSR_IA32_CORE_C3_RESIDENCY, &cl, &ch);
	c3res = (((uint64_t)ch << 32) | cl) - c3res;
	rdmsr_carefully(MSR_IA32_CORE_C6_RESIDENCY, &cl, &ch);
	c6res = (((uint64_t)ch << 32) | cl) - c6res;
	rdmsr_carefully(MSR_IA32_CORE_C7_RESIDENCY, &cl, &ch);
	c7res = (((uint64_t)ch << 32) | cl) - c7res;

	uint64_t ndelta = itime - tmrCvt(c3res + c6res + c7res, tscFCvtt2n);
	KERNEL_DEBUG_CONSTANT(0xcead0000, ndelta, itime, c7res, c6res, c3res);
	if ((itime > 1000000) && (ndelta > 250000))
		KERNEL_DEBUG_CONSTANT(0xceae0000, ndelta, itime, c7res, c6res, c3res);
#endif

	machine_idle_exit:
	/*
	 * Re-enable interrupts.
	 */

	pal_sti();

	if (do_process_pending_timers) {
		TCOAL_DEBUG(0xBBBB0000 | DBG_FUNC_START, ctime, esdeadline, ehdeadline, idle_pending_timers_processed, 0);

		/* Adjust to reflect that this isn't truly a package idle exit */
		__sync_fetch_and_sub(&my_cpu->lcpu.package->num_idle, 1);
		lapic_timer_swi(); /* Trigger software timer interrupt */
		__sync_fetch_and_add(&my_cpu->lcpu.package->num_idle, 1);

		TCOAL_DEBUG(0xBBBB0000 | DBG_FUNC_END, ctime, esdeadline, idle_pending_timers_processed, 0, 0);
	}
#if CST_DEMOTION_DEBUG
	uint64_t nwakeups = PROCESSOR_DATA(cproc, wakeups_issued_total);

	if ((nwakeups == cwakeups) && (topoParms.nLThreadsPerPackage == my_cpu->lcpu.package->num_idle)) {
		KERNEL_DEBUG_CONSTANT(0xceaa0000, cwakeups, 0, 0, 0, 0);
	}
#endif    
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
	pal_stop_cpu(FALSE);
	break;

    case PM_HALT_PANIC:
	cpup->lcpu.state = LCPU_PAUSE;
	pal_stop_cpu(TRUE);
	break;

    case PM_HALT_NORMAL:
    case PM_HALT_SLEEP:
    default:
        pal_cli();

	if (pmInitDone
	    && pmDispatch != NULL
	    && pmDispatch->pmCPUHalt != NULL) {
	    /*
	     * Halt the CPU (and put it in a low power state.
	     */
	    (*pmDispatch->pmCPUHalt)();

	    /*
	     * We've exited halt, so get the CPU schedulable again.
	     * - by calling the fast init routine for a slave, or
	     * - by returning if we're the master processor.
	     */
	    if (cpup->cpu_number != master_cpu) {
		i386_init_slave_fast();
		panic("init_slave_fast returned");
	    }
	} else
	{
	    /*
	     * If no power managment and a processor is taken off-line,
	     * then invalidate the cache and halt it (it will not be able
	     * to be brought back on-line without resetting the CPU).
	     */
	    __asm__ volatile ("wbinvd");
	    cpup->lcpu.state = LCPU_HALT;
	    pal_stop_cpu(FALSE);

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
    if (earlyTopology
	&& pmDispatch != NULL
	&& pmDispatch->pmCPUStateInit != NULL) {
	(*pmDispatch->pmCPUStateInit)();
	earlyTopology = FALSE;
    }
    pmInitDone = 1;
}

x86_lcpu_t *
pmGetLogicalCPU(int cpu)
{
    return(cpu_to_lcpu(cpu));
}

x86_lcpu_t *
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
 * Note: a return of 0 from AICPM and this routine signifies
 * that no deadline is set.
 */
uint64_t
pmCPUGetDeadline(cpu_data_t *cpu)
{
    uint64_t	deadline	= 0;

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
    kern_return_t	rc	= KERN_SUCCESS;

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
    else
	earlyTopology = TRUE;
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

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->getMaxSnoop != NULL)
	max_snoop = pmDispatch->getMaxSnoop();

    return((unsigned)(max_snoop & 0xffffffff));
}


uint32_t
ml_get_maxbusdelay(void)
{
    uint64_t	max_delay	= 0;

    if (pmInitDone
	&& pmDispatch != NULL
	&& pmDispatch->getMaxBusDelay != NULL)
	max_delay = pmDispatch->getMaxBusDelay();

    return((uint32_t)(max_delay & 0xffffffff));
}

/*
 * Advertise a memory access latency tolerance of "mdelay" ns
 */
void
ml_set_maxbusdelay(uint32_t mdelay)
{
    uint64_t	maxdelay	= mdelay;

    if (pmDispatch != NULL
	&& pmDispatch->setMaxBusDelay != NULL) {
	earlyMaxBusDelay = DELAY_UNSET;
	pmDispatch->setMaxBusDelay(maxdelay);
    } else
	earlyMaxBusDelay = maxdelay;
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
	&& pmDispatch->setMaxIntDelay != NULL) {
	earlyMaxIntDelay = DELAY_UNSET;
	pmDispatch->setMaxIntDelay(mdelay);
    } else
	earlyMaxIntDelay = mdelay;
}

boolean_t
ml_get_interrupt_prewake_applicable()
{
    boolean_t applicable = FALSE;

    if (pmInitDone 
	&& pmDispatch != NULL
	&& pmDispatch->pmInterruptPrewakeApplicable != NULL)
	applicable = pmDispatch->pmInterruptPrewakeApplicable();

    return applicable;
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

processor_t
machine_choose_processor(processor_set_t pset,
			 processor_t preferred)
{
    int		startCPU;
    int		endCPU;
    int		preferredCPU;
    int		chosenCPU;

    if (!pmInitDone)
	return(preferred);

    if (pset == NULL) {
	startCPU = -1;
	endCPU = -1;
    } else {
	startCPU = pset->cpu_set_low;
	endCPU = pset->cpu_set_hi;
    }

    if (preferred == NULL)
	preferredCPU = -1;
    else
	preferredCPU = preferred->cpu_id;

    if (pmDispatch != NULL
	&& pmDispatch->pmChooseCPU != NULL) {
	chosenCPU = pmDispatch->pmChooseCPU(startCPU, endCPU, preferredCPU);

	if (chosenCPU == -1)
	    return(NULL);
	return(cpu_datap(chosenCPU)->cpu_processor);
    }

    return(preferred);
}

static int
pmThreadGetUrgency(uint64_t *rt_period, uint64_t *rt_deadline)
{
	int             urgency;
	uint64_t        arg1, arg2;

	urgency = thread_get_urgency(current_processor()->next_thread, &arg1, &arg2);

	if (urgency == THREAD_URGENCY_REAL_TIME) {
		if (rt_period != NULL)
			*rt_period = arg1;
		
		if (rt_deadline != NULL)
			*rt_deadline = arg2;
	}

	return(urgency);
}

#if	DEBUG
uint32_t	urgency_stats[64][THREAD_URGENCY_MAX];
#endif

#define		URGENCY_NOTIFICATION_ASSERT_NS (5 * 1000 * 1000)
uint64_t	urgency_notification_assert_abstime_threshold, urgency_notification_max_recorded;

void
thread_tell_urgency(int urgency,
    uint64_t rt_period,
    uint64_t rt_deadline,
    uint64_t sched_latency,
    thread_t nthread)
{
	uint64_t	urgency_notification_time_start, delta;
	boolean_t	urgency_assert = (urgency_notification_assert_abstime_threshold != 0);
	assert(get_preemption_level() > 0 || ml_get_interrupts_enabled() == FALSE);
#if	DEBUG
	urgency_stats[cpu_number() % 64][urgency]++;
#endif
	if (!pmInitDone
	    || pmDispatch == NULL
	    || pmDispatch->pmThreadTellUrgency == NULL)
		return;

	SCHED_DEBUG_PLATFORM_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_URGENCY) | DBG_FUNC_START, urgency, rt_period, rt_deadline, sched_latency, 0);

	if (__improbable((urgency_assert == TRUE)))
		urgency_notification_time_start = mach_absolute_time();

	current_cpu_datap()->cpu_nthread = nthread;
	pmDispatch->pmThreadTellUrgency(urgency, rt_period, rt_deadline);

	if (__improbable((urgency_assert == TRUE))) {
		delta = mach_absolute_time() - urgency_notification_time_start;

		if (__improbable(delta > urgency_notification_max_recorded)) {
			/* This is not synchronized, but it doesn't matter
			 * if we (rarely) miss an event, as it is statistically
			 * unlikely that it will never recur.
			 */
			urgency_notification_max_recorded = delta;

			if (__improbable((delta > urgency_notification_assert_abstime_threshold) && !machine_timeout_suspended()))
				panic("Urgency notification callout %p exceeded threshold, 0x%llx abstime units", pmDispatch->pmThreadTellUrgency, delta);
		}
	}

	SCHED_DEBUG_PLATFORM_KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_URGENCY) | DBG_FUNC_END, urgency, rt_period, rt_deadline, 0, 0);
}

void
machine_thread_going_on_core(__unused thread_t      new_thread,
							 __unused int           urgency,
							 __unused uint64_t      sched_latency,
							 __unused uint64_t      dispatch_time)
{
}

void
machine_thread_going_off_core(__unused thread_t old_thread, __unused boolean_t thread_terminating, __unused uint64_t last_dispatch)
{
}

void
machine_max_runnable_latency(__unused uint64_t bg_max_latency,
							 __unused uint64_t default_max_latency,
							 __unused uint64_t realtime_max_latency)
{
}

void
machine_work_interval_notify(__unused thread_t thread,
							 __unused uint64_t work_interval_id,
							 __unused uint64_t start_abstime,
							 __unused uint64_t finish_abstime,
							 __unused uint64_t deadline_abstime,
							 __unused uint64_t next_start_abstime,
							 __unused uint16_t urgency,
							 __unused uint32_t flags)
{
}

void
active_rt_threads(boolean_t active)
{
    if (!pmInitDone
	|| pmDispatch == NULL
	|| pmDispatch->pmActiveRTThreads == NULL)
	return;

    pmDispatch->pmActiveRTThreads(active);
}

static uint32_t
pmGetSavedRunCount(void)
{
    return(saved_run_count);
}

/*
 * Returns the root of the package tree.
 */
x86_pkg_t *
pmGetPkgRoot(void)
{
    return(x86_pkgs);
}

static boolean_t
pmCPUGetHibernate(int cpu)
{
    return(cpu_datap(cpu)->cpu_hibernate);
}

processor_t
pmLCPUtoProcessor(int lcpu)
{
    return(cpu_datap(lcpu)->cpu_processor);
}

static void
pmReSyncDeadlines(int cpu)
{
    static boolean_t	registered	= FALSE;

    if (!registered) {
	PM_interrupt_register(&timer_resync_deadlines);
	registered = TRUE;
    }

    if ((uint32_t)cpu == current_cpu_datap()->lcpu.cpu_num)
	timer_resync_deadlines();
    else
	cpu_PM_interrupt(cpu);
}

static void
pmSendIPI(int cpu)
{
    lapic_send_ipi(cpu, LAPIC_PM_INTERRUPT);
}

static void
pmGetNanotimeInfo(pm_rtc_nanotime_t *rtc_nanotime)
{
	/*
	 * Make sure that nanotime didn't change while we were reading it.
	 */
	do {
		rtc_nanotime->generation = pal_rtc_nanotime_info.generation; /* must be first */
		rtc_nanotime->tsc_base = pal_rtc_nanotime_info.tsc_base;
		rtc_nanotime->ns_base = pal_rtc_nanotime_info.ns_base;
		rtc_nanotime->scale = pal_rtc_nanotime_info.scale;
		rtc_nanotime->shift = pal_rtc_nanotime_info.shift;
	} while(pal_rtc_nanotime_info.generation != 0
		&& rtc_nanotime->generation != pal_rtc_nanotime_info.generation);
}

uint32_t
pmTimerQueueMigrate(int target_cpu)
{
    /* Call the etimer code to do this. */
    return (target_cpu != cpu_number())
		? timer_queue_migrate_cpu(target_cpu)
		: 0;
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
		callbacks->GetNanotimeInfo	= pmGetNanotimeInfo;
		callbacks->ThreadGetUrgency	= pmThreadGetUrgency;
		callbacks->RTCClockAdjust	= rtc_clock_adjust;
		callbacks->timerQueueMigrate    = pmTimerQueueMigrate;
		callbacks->topoParms            = &topoParms;
		callbacks->pmSendIPI		= pmSendIPI;
		callbacks->InterruptPending	= lapic_is_interrupt_pending;
		callbacks->IsInterrupting	= lapic_is_interrupting;
		callbacks->InterruptStats	= lapic_interrupt_counts;
		callbacks->DisableApicTimer	= lapic_disable_timer;
	} else {
		panic("Version mis-match between Kernel and CPU PM");
	}

	if (cpuFuncs != NULL) {
		if (pmDispatch) {
			panic("Attempt to re-register power management interface--AICPM present in xcpm mode? %p->%p", pmDispatch, cpuFuncs);
		}

		pmDispatch = cpuFuncs;

		if (earlyTopology
		    && pmDispatch->pmCPUStateInit != NULL) {
			(*pmDispatch->pmCPUStateInit)();
			earlyTopology = FALSE;
		}

		if (pmDispatch->pmIPIHandler != NULL) {
			lapic_set_pm_func((i386_intr_func_t)pmDispatch->pmIPIHandler);
		}
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

void machine_track_platform_idle(boolean_t entry) {
	cpu_data_t		*my_cpu		= current_cpu_datap();

	if (entry) {
		(void)__sync_fetch_and_add(&my_cpu->lcpu.package->num_idle, 1);
	}
 	else {
 		uint32_t nidle = __sync_fetch_and_sub(&my_cpu->lcpu.package->num_idle, 1);
 		if (nidle == topoParms.nLThreadsPerPackage) {
 			my_cpu->lcpu.package->package_idle_exits++;
 		}
 	}
}
