/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

extern "C" {
#include <kern/debug.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kperf/kperf.h>
#include <pexpert/pexpert.h>
#include <machine/machine_routines.h>
};

#include <libkern/OSAtomic.h>
#include <libkern/c++/OSCollection.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformActions.h>
#include <IOKit/IOPMGR.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/PassthruInterruptController.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <Kernel/IOKitKernelInternal.h>

#if USE_APPLEARMSMP

// FIXME: These are in <kern/misc_protos.h> but that file has other deps that aren't being resolved
extern "C" void console_suspend();
extern "C" void console_resume();

static PassthruInterruptController *gCPUIC;
static IOPMGR *gPMGR;
static IOInterruptController *gAIC;
static bool aic_ipis = false;
static const ml_topology_info *topology_info;

// cpu_id of the boot processor
static unsigned int boot_cpu;

// array index is a cpu_id (so some elements may be NULL)
static processor_t *machProcessors;

static void
processor_idle_wrapper(cpu_id_t /*cpu_id*/, boolean_t enter, uint64_t *new_timeout_ticks)
{
	if (enter) {
		gPMGR->enterCPUIdle(new_timeout_ticks);
	} else {
		gPMGR->exitCPUIdle(new_timeout_ticks);
	}
}

static void
idle_timer_wrapper(void */*refCon*/, uint64_t *new_timeout_ticks)
{
	gPMGR->updateCPUIdle(new_timeout_ticks);
}

static void
register_aic_handlers(const ml_topology_cpu *cpu_info,
    ipi_handler_t ipi_handler,
    perfmon_interrupt_handler_func pmi_handler)
{
	const int n_irqs = 3;
	int i;
	IOInterruptVectorNumber irqlist[n_irqs] = {
		cpu_info->self_ipi_irq,
		cpu_info->other_ipi_irq,
		cpu_info->pmi_irq };

	IOService *fakeCPU = new IOService();
	if (!fakeCPU || !fakeCPU->init()) {
		panic("Can't initialize fakeCPU");
	}

	IOInterruptSource source[n_irqs];
	for (i = 0; i < n_irqs; i++) {
		source[i].vectorData = OSData::withBytes(&irqlist[i], sizeof(irqlist[0]));
	}
	fakeCPU->_interruptSources = source;

	if (cpu_info->self_ipi_irq && cpu_info->other_ipi_irq) {
		// Legacy configuration, for !HAS_IPI chips (pre-Skye).
		if (gAIC->registerInterrupt(fakeCPU, 0, NULL, (IOInterruptHandler)ipi_handler, NULL) != kIOReturnSuccess ||
		    gAIC->enableInterrupt(fakeCPU, 0) != kIOReturnSuccess ||
		    gAIC->registerInterrupt(fakeCPU, 1, NULL, (IOInterruptHandler)ipi_handler, NULL) != kIOReturnSuccess ||
		    gAIC->enableInterrupt(fakeCPU, 1) != kIOReturnSuccess) {
			panic("Error registering IPIs");
		}
#if !defined(HAS_IPI)
		// Ideally this should be decided by EDT, but first we need to update EDT
		// to default to fast IPIs on modern platforms.
		aic_ipis = true;
#endif
	}
	// Conditional, because on Skye and later, we use an FIQ instead of an external IRQ.
	if (pmi_handler && cpu_info->pmi_irq) {
		if (gAIC->registerInterrupt(fakeCPU, 2, NULL, (IOInterruptHandler)pmi_handler, NULL) != kIOReturnSuccess ||
		    gAIC->enableInterrupt(fakeCPU, 2) != kIOReturnSuccess) {
			panic("Error registering PMI");
		}
	}

	for (i = 0; i < n_irqs; i++) {
		source[i].vectorData->release();
	}
}

static void
cpu_boot_thread(void */*unused0*/, wait_result_t /*unused1*/)
{
	OSDictionary *matching = IOService::serviceMatching("IOPlatformExpert");
	IOService::waitForMatchingService(matching, UINT64_MAX);
	matching->release();

	gCPUIC = new PassthruInterruptController;
	if (!gCPUIC || !gCPUIC->init()) {
		panic("Can't initialize PassthruInterruptController");
	}
	gAIC = static_cast<IOInterruptController *>(gCPUIC->waitForChildController());

	ml_set_max_cpus(topology_info->max_cpu_id + 1);

	matching = IOService::serviceMatching("IOPMGR");
	gPMGR = OSDynamicCast(IOPMGR,
	    IOService::waitForMatchingService(matching, UINT64_MAX));
	matching->release();

	const size_t array_size = (topology_info->max_cpu_id + 1) * sizeof(*machProcessors);
	machProcessors = static_cast<processor_t *>(IOMalloc(array_size));
	if (!machProcessors) {
		panic("Can't allocate machProcessors array");
	}
	memset(machProcessors, 0, array_size);

	ml_cpu_init_state();
	for (unsigned int cpu = 0; cpu < topology_info->num_cpus; cpu++) {
		const ml_topology_cpu *cpu_info = &topology_info->cpus[cpu];
		const unsigned int cpu_id = cpu_info->cpu_id;
		ml_processor_info_t this_processor_info;
		ipi_handler_t ipi_handler;
		perfmon_interrupt_handler_func pmi_handler;

		memset(&this_processor_info, 0, sizeof(this_processor_info));
		this_processor_info.cpu_id = reinterpret_cast<cpu_id_t>(cpu_id);
		this_processor_info.phys_id = cpu_info->phys_id;
		this_processor_info.log_id = cpu_id;
		this_processor_info.cluster_id = cpu_info->cluster_id;
		this_processor_info.cluster_type = cpu_info->cluster_type;
		this_processor_info.l2_cache_size = cpu_info->l2_cache_size;
		this_processor_info.l2_cache_id = cpu_info->l2_cache_id;
		this_processor_info.l3_cache_size = cpu_info->l3_cache_size;
		this_processor_info.l3_cache_id = cpu_info->l3_cache_id;

		gPMGR->initCPUIdle(&this_processor_info);
		this_processor_info.processor_idle = &processor_idle_wrapper;
		this_processor_info.idle_timer = &idle_timer_wrapper;

		kern_return_t result = ml_processor_register(&this_processor_info,
		    &machProcessors[cpu_id], &ipi_handler, &pmi_handler);
		if (result == KERN_FAILURE) {
			panic("ml_processor_register failed: %d", result);
		}
		register_aic_handlers(cpu_info, ipi_handler, pmi_handler);

		if (processor_start(machProcessors[cpu_id]) != KERN_SUCCESS) {
			panic("processor_start failed");
		}
	}
	IOService::publishResource(gIOAllCPUInitializedKey, kOSBooleanTrue);
}

void
IOCPUInitialize(void)
{
	topology_info = ml_get_topology_info();
	boot_cpu = topology_info->boot_cpu->cpu_id;

	thread_t thread;
	kernel_thread_start(&cpu_boot_thread, NULL, &thread);
	thread_set_thread_name(thread, "cpu_boot_thread");
	thread_deallocate(thread);
}

static unsigned int
target_to_cpu_id(cpu_id_t in)
{
	return (unsigned int)(uintptr_t)in;
}

// Release a secondary CPU from reset.  Runs from a different CPU (obviously).
kern_return_t
PE_cpu_start(cpu_id_t target,
    vm_offset_t /*start_paddr*/, vm_offset_t /*arg_paddr*/)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (cpu_id != boot_cpu) {
		gPMGR->enableCPUCore(cpu_id);
	}
	return KERN_SUCCESS;
}

// Initialize a CPU when it first comes up.  Runs on the target CPU.
// |bootb| is true on the initial boot, false on S2R resume.
void
PE_cpu_machine_init(cpu_id_t target, boolean_t bootb)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (!bootb && cpu_id == boot_cpu && ml_is_quiescing()) {
		IOCPURunPlatformActiveActions();
	}

	ml_broadcast_cpu_event(CPU_BOOTED, cpu_id);

	// Send myself an IPI to clear SIGPdisabled.  Hang here if IPIs are broken.
	// (Probably only works on the boot CPU.)
	PE_cpu_signal(target, target);
	while (ml_get_interrupts_enabled() && !ml_cpu_signal_is_enabled()) {
		OSMemoryBarrier();
	}
}

void
PE_cpu_halt(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);
	processor_exit(machProcessors[cpu_id]);
}

void
PE_cpu_signal(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->sendIPI(cpu->cpu_id, false);
	} else {
		ml_cpu_signal(cpu->phys_id);
	}
}

void
PE_cpu_signal_deferred(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->sendIPI(cpu->cpu_id, true);
	} else {
		ml_cpu_signal_deferred(cpu->phys_id);
	}
}

void
PE_cpu_signal_cancel(cpu_id_t /*source*/, cpu_id_t target)
{
	struct ml_topology_cpu *cpu = &topology_info->cpus[target_to_cpu_id(target)];
	if (aic_ipis) {
		gAIC->cancelDeferredIPI(cpu->cpu_id);
	} else {
		ml_cpu_signal_retract(cpu->phys_id);
	}
}

// Brings down one CPU core for S2R.  Runs on the target CPU.
void
PE_cpu_machine_quiesce(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);

	if (cpu_id == boot_cpu) {
		IOCPURunPlatformQuiesceActions();
	} else {
		gPMGR->disableCPUCore(cpu_id);
	}

	ml_broadcast_cpu_event(CPU_DOWN, cpu_id);
	ml_arm_sleep();
}

// Takes one secondary CPU core offline at runtime.  Runs on the target CPU.
// Returns true if the platform code should go into deep sleep WFI, false otherwise.
bool
PE_cpu_down(cpu_id_t target)
{
	unsigned int cpu_id = target_to_cpu_id(target);
	assert(cpu_id != boot_cpu);
	gPMGR->disableCPUCore(cpu_id);
	return false;
}

void
PE_handle_ext_interrupt(void)
{
	gCPUIC->externalInterrupt();
}

void
IOCPUSleepKernel(void)
{
	IOPMrootDomain  *rootDomain = IOService::getPMRootDomain();
	unsigned int i;

	printf("IOCPUSleepKernel enter\n");
#if defined(__arm64__)
	sched_override_recommended_cores_for_sleep();
#endif

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformActions );
	IOPlatformActionsPreSleep();
	rootDomain->tracePoint( kIOPMTracePointSleepCPUs );

	integer_t old_pri;
	thread_t self = current_thread();

	/*
	 * We need to boost this thread's priority to the maximum kernel priority to
	 * ensure we can urgently preempt ANY thread currently executing on the
	 * target CPU.  Note that realtime threads have their own mechanism to eventually
	 * demote their priority below MAXPRI_KERNEL if they hog the CPU for too long.
	 */
	old_pri = thread_kern_get_pri(self);
	thread_kern_set_pri(self, thread_kern_get_kernel_maxpri());

	// Sleep the non-boot CPUs.
	ml_set_is_quiescing(true);
	for (i = 0; i < topology_info->num_cpus; i++) {
		unsigned int cpu_id = topology_info->cpus[i].cpu_id;
		if (cpu_id != boot_cpu) {
			processor_exit(machProcessors[cpu_id]);
		}
	}

	console_suspend();

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformDriver );
	rootDomain->stop_watchdog_timer();

	/*
	 * Now sleep the boot CPU, including calling the kQueueQuiesce actions.
	 * The system sleeps here.
	 */
	processor_exit(machProcessors[boot_cpu]);

	/*
	 * The system is now coming back from sleep on the boot CPU.
	 * The kQueueActive actions have already been called.
	 */

	ml_set_is_quiescing(false);
	rootDomain->start_watchdog_timer();
	rootDomain->tracePoint( kIOPMTracePointWakePlatformActions );

	console_resume();

	IOPlatformActionsPostResume();
	rootDomain->tracePoint( kIOPMTracePointWakeCPUs );

	for (i = 0; i < topology_info->num_cpus; i++) {
		unsigned int cpu_id = topology_info->cpus[i].cpu_id;
		if (cpu_id != boot_cpu) {
			processor_start(machProcessors[cpu_id]);
		}
	}

#if defined(__arm64__)
	sched_restore_recommended_cores_after_sleep();
#endif

	thread_kern_set_pri(self, old_pri);
	printf("IOCPUSleepKernel exit\n");
}

#endif /* USE_APPLEARMSMP */
