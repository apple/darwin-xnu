/*
 * Copyright (c) 1999-2016 Apple Inc.  All rights reserved.
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

#define IOKIT_ENABLE_SHARED_PTR

extern "C" {
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <kern/cpu_number.h>
extern void kperf_kernel_configure(char *);
}

#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <libkern/c++/OSSharedPtr.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOCPU.h>
#include "IOKitKernelInternal.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <kern/queue.h>
#include <kern/sched_prim.h>

extern "C" void console_suspend();
extern "C" void console_resume();
extern "C" void sched_override_recommended_cores_for_sleep(void);
extern "C" void sched_restore_recommended_cores_after_sleep(void);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOLock *gIOCPUsLock;
static OSSharedPtr<OSArray> gIOCPUs;
static OSSharedPtr<const OSSymbol> gIOCPUStateKey;
static OSSharedPtr<OSString> gIOCPUStateNames[kIOCPUStateCount];

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !USE_APPLEARMSMP

void
IOCPUInitialize(void)
{
	gIOCPUsLock = IOLockAlloc();
	gIOCPUs     = OSArray::withCapacity(1);

	gIOCPUStateKey = OSSymbol::withCStringNoCopy("IOCPUState");

	gIOCPUStateNames[kIOCPUStateUnregistered] =
	    OSString::withCStringNoCopy("Unregistered");
	gIOCPUStateNames[kIOCPUStateUninitalized] =
	    OSString::withCStringNoCopy("Uninitalized");
	gIOCPUStateNames[kIOCPUStateStopped] =
	    OSString::withCStringNoCopy("Stopped");
	gIOCPUStateNames[kIOCPUStateRunning] =
	    OSString::withCStringNoCopy("Running");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
PE_cpu_start(cpu_id_t target,
    vm_offset_t start_paddr, vm_offset_t arg_paddr)
{
	IOCPU *targetCPU = (IOCPU *)target;

	if (targetCPU == NULL) {
		return KERN_FAILURE;
	}
	return targetCPU->startCPU(start_paddr, arg_paddr);
}

void
PE_cpu_halt(cpu_id_t target)
{
	IOCPU *targetCPU = (IOCPU *)target;

	targetCPU->haltCPU();
}

void
PE_cpu_signal(cpu_id_t source, cpu_id_t target)
{
	IOCPU *sourceCPU = (IOCPU *)source;
	IOCPU *targetCPU = (IOCPU *)target;

	sourceCPU->signalCPU(targetCPU);
}

void
PE_cpu_signal_deferred(cpu_id_t source, cpu_id_t target)
{
	IOCPU *sourceCPU = (IOCPU *)source;
	IOCPU *targetCPU = (IOCPU *)target;

	sourceCPU->signalCPUDeferred(targetCPU);
}

void
PE_cpu_signal_cancel(cpu_id_t source, cpu_id_t target)
{
	IOCPU *sourceCPU = (IOCPU *)source;
	IOCPU *targetCPU = (IOCPU *)target;

	sourceCPU->signalCPUCancel(targetCPU);
}

void
PE_cpu_machine_init(cpu_id_t target, boolean_t bootb)
{
	IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);

	if (targetCPU == NULL) {
		panic("%s: invalid target CPU %p", __func__, target);
	}

	targetCPU->initCPU(bootb);
#if defined(__arm__) || defined(__arm64__)
	if (!bootb && (targetCPU->getCPUNumber() == (UInt32)master_cpu)) {
		ml_set_is_quiescing(false);
	}
#endif /* defined(__arm__) || defined(__arm64__) */
}

void
PE_cpu_machine_quiesce(cpu_id_t target)
{
	IOCPU *targetCPU = (IOCPU*)target;
#if defined(__arm__) || defined(__arm64__)
	if (targetCPU->getCPUNumber() == (UInt32)master_cpu) {
		ml_set_is_quiescing(true);
	}
#endif /* defined(__arm__) || defined(__arm64__) */
	targetCPU->quiesceCPU();
}

#if defined(__arm__) || defined(__arm64__)
static perfmon_interrupt_handler_func pmi_handler = NULL;

kern_return_t
PE_cpu_perfmon_interrupt_install_handler(perfmon_interrupt_handler_func handler)
{
	pmi_handler = handler;

	return KERN_SUCCESS;
}

void
PE_cpu_perfmon_interrupt_enable(cpu_id_t target, boolean_t enable)
{
	IOCPU *targetCPU = (IOCPU*)target;

	if (targetCPU == nullptr) {
		return;
	}

	if (enable) {
		targetCPU->getProvider()->registerInterrupt(1, targetCPU, (IOInterruptAction)pmi_handler, NULL);
		targetCPU->getProvider()->enableInterrupt(1);
	} else {
		targetCPU->getProvider()->disableInterrupt(1);
	}
}
#endif

#endif /* !USE_APPLEARMSMP */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndAbstractStructors(IOCPU, IOService);
OSMetaClassDefineReservedUnused(IOCPU, 0);
OSMetaClassDefineReservedUnused(IOCPU, 1);
OSMetaClassDefineReservedUnused(IOCPU, 2);
OSMetaClassDefineReservedUnused(IOCPU, 3);
OSMetaClassDefineReservedUnused(IOCPU, 4);
OSMetaClassDefineReservedUnused(IOCPU, 5);
OSMetaClassDefineReservedUnused(IOCPU, 6);
OSMetaClassDefineReservedUnused(IOCPU, 7);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !USE_APPLEARMSMP
void
IOCPUSleepKernel(void)
{
#if defined(__x86_64__)
	extern IOCPU *currentShutdownTarget;
#endif
	unsigned int cnt, numCPUs;
	IOCPU *target;
	IOCPU *bootCPU = NULL;
	IOPMrootDomain  *rootDomain = IOService::getPMRootDomain();

	printf("IOCPUSleepKernel enter\n");
#if defined(__arm64__)
	sched_override_recommended_cores_for_sleep();
#endif

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformActions );
	IOPlatformActionsPreSleep();
	rootDomain->tracePoint( kIOPMTracePointSleepCPUs );

	numCPUs = gIOCPUs->getCount();
#if defined(__x86_64__)
	currentShutdownTarget = NULL;
#endif

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

	// Sleep the CPUs.
	ml_set_is_quiescing(true);
	cnt = numCPUs;
	while (cnt--) {
		target = OSDynamicCast(IOCPU, gIOCPUs->getObject(cnt));

		// We make certain that the bootCPU is the last to sleep
		// We'll skip it for now, and halt it after finishing the
		// non-boot CPU's.
		if (target->getCPUNumber() == (UInt32)master_cpu) {
			bootCPU = target;
		} else if (target->getCPUState() == kIOCPUStateRunning) {
#if defined(__x86_64__)
			currentShutdownTarget = target;
#endif
			target->haltCPU();
		}
	}

	assert(bootCPU != NULL);
	assert(cpu_number() == master_cpu);

	console_suspend();

	rootDomain->tracePoint( kIOPMTracePointSleepPlatformDriver );
	rootDomain->stop_watchdog_timer();

	/*
	 * Now sleep the boot CPU, including calling the kQueueQuiesce actions.
	 * The system sleeps here.
	 */

	bootCPU->haltCPU();
	ml_set_is_quiescing(false);

	/*
	 * The system is now coming back from sleep on the boot CPU.
	 * The kQueueActive actions have already been called.
	 */

	rootDomain->start_watchdog_timer();
	rootDomain->tracePoint( kIOPMTracePointWakePlatformActions );

	console_resume();

	IOPlatformActionsPostResume();
	rootDomain->tracePoint( kIOPMTracePointWakeCPUs );

	// Wake the other CPUs.
	for (cnt = 0; cnt < numCPUs; cnt++) {
		target = OSDynamicCast(IOCPU, gIOCPUs->getObject(cnt));

		// Skip the already-woken boot CPU.
		if (target->getCPUNumber() != (UInt32)master_cpu) {
			if (target->getCPUState() == kIOCPUStateRunning) {
				panic("Spurious wakeup of cpu %u", (unsigned int)(target->getCPUNumber()));
			}

			if (target->getCPUState() == kIOCPUStateStopped) {
				processor_start(target->getMachProcessor());
			}
		}
	}

#if defined(__arm64__)
	sched_restore_recommended_cores_after_sleep();
#endif

	thread_kern_set_pri(self, old_pri);
	printf("IOCPUSleepKernel exit\n");
}

static bool
is_IOCPU_disabled(void)
{
	return false;
}
#else /* !USE_APPLEARMSMP */
static bool
is_IOCPU_disabled(void)
{
	return true;
}
#endif /* !USE_APPLEARMSMP */

bool
IOCPU::start(IOService *provider)
{
	if (is_IOCPU_disabled()) {
		return false;
	}

	if (!super::start(provider)) {
		return false;
	}

	_cpuGroup = gIOCPUs;
	cpuNub = provider;

	IOLockLock(gIOCPUsLock);
	gIOCPUs->setObject(this);
	IOLockUnlock(gIOCPUsLock);

	// Correct the bus, cpu and timebase frequencies in the device tree.
	if (gPEClockFrequencyInfo.bus_frequency_hz < 0x100000000ULL) {
		OSSharedPtr<OSData> busFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.bus_clock_rate_hz, 4);
		provider->setProperty("bus-frequency", busFrequency.get());
	} else {
		OSSharedPtr<OSData> busFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.bus_frequency_hz, 8);
		provider->setProperty("bus-frequency", busFrequency.get());
	}

	if (gPEClockFrequencyInfo.cpu_frequency_hz < 0x100000000ULL) {
		OSSharedPtr<OSData> cpuFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.cpu_clock_rate_hz, 4);
		provider->setProperty("clock-frequency", cpuFrequency.get());
	} else {
		OSSharedPtr<OSData> cpuFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.cpu_frequency_hz, 8);
		provider->setProperty("clock-frequency", cpuFrequency.get());
	}

	OSSharedPtr<OSData> timebaseFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.timebase_frequency_hz, 4);
	provider->setProperty("timebase-frequency", timebaseFrequency.get());

	super::setProperty("IOCPUID", getRegistryEntryID(), sizeof(uint64_t) * 8);

	setCPUNumber(0);
	setCPUState(kIOCPUStateUnregistered);

	return true;
}

void
IOCPU::detach(IOService *provider)
{
	if (is_IOCPU_disabled()) {
		return;
	}

	super::detach(provider);
	IOLockLock(gIOCPUsLock);
	unsigned int index = gIOCPUs->getNextIndexOfObject(this, 0);
	if (index != (unsigned int)-1) {
		gIOCPUs->removeObject(index);
	}
	IOLockUnlock(gIOCPUsLock);
}

OSObject *
IOCPU::getProperty(const OSSymbol *aKey) const
{
	if (aKey == gIOCPUStateKey) {
		return gIOCPUStateNames[_cpuState].get();
	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	return super::getProperty(aKey);
#pragma clang diagnostic pop
}

bool
IOCPU::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
	if (aKey == gIOCPUStateKey) {
		return false;
	}

	return super::setProperty(aKey, anObject);
}

bool
IOCPU::serializeProperties(OSSerialize *serialize) const
{
	bool result;
	OSSharedPtr<OSDictionary> dict = dictionaryWithProperties();
	if (!dict) {
		return false;
	}
	dict->setObject(gIOCPUStateKey.get(), gIOCPUStateNames[_cpuState].get());
	result = dict->serialize(serialize);
	return result;
}

IOReturn
IOCPU::setProperties(OSObject *properties)
{
	OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
	OSString     *stateStr;
	IOReturn     result;

	if (dict == NULL) {
		return kIOReturnUnsupported;
	}

	stateStr = OSDynamicCast(OSString, dict->getObject(gIOCPUStateKey.get()));
	if (stateStr != NULL) {
		result = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
		if (result != kIOReturnSuccess) {
			return result;
		}

		if (setProperty(gIOCPUStateKey.get(), stateStr)) {
			return kIOReturnSuccess;
		}

		return kIOReturnUnsupported;
	}

	return kIOReturnUnsupported;
}

void
IOCPU::signalCPU(IOCPU */*target*/)
{
}

void
IOCPU::signalCPUDeferred(IOCPU *target)
{
	// Our CPU may not support deferred IPIs,
	// so send a regular IPI by default
	signalCPU(target);
}

void
IOCPU::signalCPUCancel(IOCPU */*target*/)
{
	// Meant to cancel signals sent by
	// signalCPUDeferred; unsupported
	// by default
}

void
IOCPU::enableCPUTimeBase(bool /*enable*/)
{
}

UInt32
IOCPU::getCPUNumber(void)
{
	return _cpuNumber;
}

void
IOCPU::setCPUNumber(UInt32 cpuNumber)
{
	_cpuNumber = cpuNumber;
	super::setProperty("IOCPUNumber", _cpuNumber, 32);
}

UInt32
IOCPU::getCPUState(void)
{
	return _cpuState;
}

void
IOCPU::setCPUState(UInt32 cpuState)
{
	if (cpuState < kIOCPUStateCount) {
		_cpuState = cpuState;
	}
}

OSArray *
IOCPU::getCPUGroup(void)
{
	return _cpuGroup.get();
}

UInt32
IOCPU::getCPUGroupSize(void)
{
	return _cpuGroup->getCount();
}

processor_t
IOCPU::getMachProcessor(void)
{
	return machProcessor;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOInterruptController

OSDefineMetaClassAndStructors(IOCPUInterruptController, IOInterruptController);

OSMetaClassDefineReservedUnused(IOCPUInterruptController, 1);
OSMetaClassDefineReservedUnused(IOCPUInterruptController, 2);
OSMetaClassDefineReservedUnused(IOCPUInterruptController, 3);
OSMetaClassDefineReservedUnused(IOCPUInterruptController, 4);
OSMetaClassDefineReservedUnused(IOCPUInterruptController, 5);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn
IOCPUInterruptController::initCPUInterruptController(int sources)
{
	return initCPUInterruptController(sources, sources);
}

IOReturn
IOCPUInterruptController::initCPUInterruptController(int sources, int cpus)
{
	int cnt;

	if (!super::init()) {
		return kIOReturnInvalid;
	}

	numSources = sources;
	numCPUs = cpus;

	vectors = (IOInterruptVector *)IOMalloc(numSources * sizeof(IOInterruptVector));
	if (vectors == NULL) {
		return kIOReturnNoMemory;
	}
	bzero(vectors, numSources * sizeof(IOInterruptVector));

	// Allocate a lock for each vector
	for (cnt = 0; cnt < numSources; cnt++) {
		vectors[cnt].interruptLock = IOLockAlloc();
		if (vectors[cnt].interruptLock == NULL) {
			for (cnt = 0; cnt < numSources; cnt++) {
				if (vectors[cnt].interruptLock != NULL) {
					IOLockFree(vectors[cnt].interruptLock);
				}
			}
			return kIOReturnNoResources;
		}
	}

	ml_set_max_cpus(numSources);
	return kIOReturnSuccess;
}

void
IOCPUInterruptController::registerCPUInterruptController(void)
{
	setProperty(gPlatformInterruptControllerName, kOSBooleanTrue);
	registerService();

	getPlatform()->registerInterruptController(gPlatformInterruptControllerName,
	    this);
}

void
IOCPUInterruptController::setCPUInterruptProperties(IOService *service)
{
	int          cnt;
	OSSharedPtr<OSArray> specifier;
	OSSharedPtr<OSArray> controller;
	long         tmpLong;

	if ((service->propertyExists(gIOInterruptControllersKey)) &&
	    (service->propertyExists(gIOInterruptSpecifiersKey))) {
		return;
	}

	// Create the interrupt specifer array.
	specifier = OSArray::withCapacity(numSources);
	for (cnt = 0; cnt < numSources; cnt++) {
		tmpLong = cnt;
		OSSharedPtr<OSData> tmpData = OSData::withBytes(&tmpLong, sizeof(tmpLong));
		specifier->setObject(tmpData.get());
	}

	// Create the interrupt controller array.
	controller = OSArray::withCapacity(numSources);
	for (cnt = 0; cnt < numSources; cnt++) {
		controller->setObject(gPlatformInterruptControllerName);
	}

	// Put the two arrays into the property table.
	service->setProperty(gIOInterruptControllersKey, controller.get());
	service->setProperty(gIOInterruptSpecifiersKey, specifier.get());
}

void
IOCPUInterruptController::enableCPUInterrupt(IOCPU *cpu)
{
	IOInterruptHandler handler = OSMemberFunctionCast(
		IOInterruptHandler, this, &IOCPUInterruptController::handleInterrupt);

	assert(numCPUs > 0);

	ml_install_interrupt_handler(cpu, cpu->getCPUNumber(), this, handler, NULL);

	IOTakeLock(vectors[0].interruptLock);
	++enabledCPUs;

	if (enabledCPUs == numCPUs) {
		IOService::cpusRunning();
		thread_wakeup(this);
	}
	IOUnlock(vectors[0].interruptLock);
}

IOReturn
IOCPUInterruptController::registerInterrupt(IOService *nub,
    int source,
    void *target,
    IOInterruptHandler handler,
    void *refCon)
{
	IOInterruptVector *vector;

	// Interrupts must be enabled, as this can allocate memory.
	assert(ml_get_interrupts_enabled() == TRUE);

	if (source >= numSources) {
		return kIOReturnNoResources;
	}

	vector = &vectors[source];

	// Get the lock for this vector.
	IOTakeLock(vector->interruptLock);

	// Make sure the vector is not in use.
	if (vector->interruptRegistered) {
		IOUnlock(vector->interruptLock);
		return kIOReturnNoResources;
	}

	// Fill in vector with the client's info.
	vector->handler = handler;
	vector->nub     = nub;
	vector->source  = source;
	vector->target  = target;
	vector->refCon  = refCon;

	// Get the vector ready.  It starts hard disabled.
	vector->interruptDisabledHard = 1;
	vector->interruptDisabledSoft = 1;
	vector->interruptRegistered   = 1;

	IOUnlock(vector->interruptLock);

	IOTakeLock(vectors[0].interruptLock);
	if (enabledCPUs != numCPUs) {
		assert_wait(this, THREAD_UNINT);
		IOUnlock(vectors[0].interruptLock);
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		IOUnlock(vectors[0].interruptLock);
	}

	return kIOReturnSuccess;
}

IOReturn
IOCPUInterruptController::getInterruptType(IOService */*nub*/,
    int /*source*/,
    int *interruptType)
{
	if (interruptType == NULL) {
		return kIOReturnBadArgument;
	}

	*interruptType = kIOInterruptTypeLevel;

	return kIOReturnSuccess;
}

IOReturn
IOCPUInterruptController::enableInterrupt(IOService */*nub*/,
    int /*source*/)
{
//  ml_set_interrupts_enabled(true);
	return kIOReturnSuccess;
}

IOReturn
IOCPUInterruptController::disableInterrupt(IOService */*nub*/,
    int /*source*/)
{
//  ml_set_interrupts_enabled(false);
	return kIOReturnSuccess;
}

IOReturn
IOCPUInterruptController::causeInterrupt(IOService */*nub*/,
    int /*source*/)
{
	ml_cause_interrupt();
	return kIOReturnSuccess;
}

IOReturn
IOCPUInterruptController::handleInterrupt(void */*refCon*/,
    IOService */*nub*/,
    int source)
{
	IOInterruptVector *vector;

	vector = &vectors[source];

	if (!vector->interruptRegistered) {
		return kIOReturnInvalid;
	}

	vector->handler(vector->target, vector->refCon,
	    vector->nub, vector->source);

	return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
