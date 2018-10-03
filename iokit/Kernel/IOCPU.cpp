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
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOCPU.h>
#include "IOKitKernelInternal.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#include <kern/queue.h>

extern "C" void console_suspend();
extern "C" void console_resume();

typedef kern_return_t (*iocpu_platform_action_t)(void * refcon0, void * refcon1, uint32_t priority,
						 void * param1, void * param2, void * param3,
						 const char * name);

struct iocpu_platform_action_entry
{
    queue_chain_t                     link;
    iocpu_platform_action_t           action;
    int32_t	                      priority;
    const char *		      name;
    void *	                      refcon0;
    void *			      refcon1;
    boolean_t			      callout_in_progress;
    struct iocpu_platform_action_entry * alloc_list;
};
typedef struct iocpu_platform_action_entry iocpu_platform_action_entry_t;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOLock *gIOCPUsLock;
static OSArray *gIOCPUs;
static const OSSymbol *gIOCPUStateKey;
static OSString *gIOCPUStateNames[kIOCPUStateCount];

enum
{
    kQueueSleep       = 0,
    kQueueWake        = 1,
    kQueueQuiesce     = 2,
    kQueueActive      = 3,
    kQueueHaltRestart = 4,
    kQueuePanic       = 5,
    kQueueCount       = 6
};

const OSSymbol *		gIOPlatformSleepActionKey;
const OSSymbol *		gIOPlatformWakeActionKey;
const OSSymbol *		gIOPlatformQuiesceActionKey;
const OSSymbol *		gIOPlatformActiveActionKey;
const OSSymbol *		gIOPlatformHaltRestartActionKey;
const OSSymbol *		gIOPlatformPanicActionKey;

static queue_head_t     	gActionQueues[kQueueCount];
static const OSSymbol *		gActionSymbols[kQueueCount];

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
iocpu_add_platform_action(queue_head_t * queue, iocpu_platform_action_entry_t * entry)
{
    iocpu_platform_action_entry_t * next;

    queue_iterate(queue, next, iocpu_platform_action_entry_t *, link)
    {
	if (next->priority > entry->priority)
	{
	    queue_insert_before(queue, entry, next, iocpu_platform_action_entry_t *, link);
	    return;
	}
    }
    queue_enter(queue, entry, iocpu_platform_action_entry_t *, link);	// at tail
}

static void
iocpu_remove_platform_action(iocpu_platform_action_entry_t * entry)
{
    remque(&entry->link);
}

static kern_return_t
iocpu_run_platform_actions(queue_head_t * queue, uint32_t first_priority, uint32_t last_priority,
					void * param1, void * param2, void * param3, boolean_t allow_nested_callouts)
{
    kern_return_t                ret = KERN_SUCCESS;
    kern_return_t                result = KERN_SUCCESS;
    iocpu_platform_action_entry_t * next;

    queue_iterate(queue, next, iocpu_platform_action_entry_t *, link)
    {
	uint32_t pri = (next->priority < 0) ? -next->priority : next->priority;
	if ((pri >= first_priority) && (pri <= last_priority))
	{
	    //kprintf("[%p]", next->action);
	    if (!allow_nested_callouts && !next->callout_in_progress)
	    {
		next->callout_in_progress = TRUE;
		ret = (*next->action)(next->refcon0, next->refcon1, pri, param1, param2, param3, next->name);
		next->callout_in_progress = FALSE;
	    }
	    else if (allow_nested_callouts)
	    {
		ret = (*next->action)(next->refcon0, next->refcon1, pri, param1, param2, param3, next->name);
	    }
	}
	if (KERN_SUCCESS == result)
	    result = ret;
    }
    return (result);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" kern_return_t 
IOCPURunPlatformQuiesceActions(void)
{
    return (iocpu_run_platform_actions(&gActionQueues[kQueueQuiesce], 0, 0U-1,
				    NULL, NULL, NULL, TRUE));
}

extern "C" kern_return_t 
IOCPURunPlatformActiveActions(void)
{
    return (iocpu_run_platform_actions(&gActionQueues[kQueueActive], 0, 0U-1,
				    NULL, NULL, NULL, TRUE));
}

extern "C" kern_return_t 
IOCPURunPlatformHaltRestartActions(uint32_t message)
{
    if (!gActionQueues[kQueueHaltRestart].next) return (kIOReturnNotReady);
    return (iocpu_run_platform_actions(&gActionQueues[kQueueHaltRestart], 0, 0U-1,
				     (void *)(uintptr_t) message, NULL, NULL, TRUE));
}

extern "C" kern_return_t 
IOCPURunPlatformPanicActions(uint32_t message)
{
    // Don't allow nested calls of panic actions
    if (!gActionQueues[kQueuePanic].next) return (kIOReturnNotReady);
    return (iocpu_run_platform_actions(&gActionQueues[kQueuePanic], 0, 0U-1,
				     (void *)(uintptr_t) message, NULL, NULL, FALSE));
}


extern "C" kern_return_t
IOCPURunPlatformPanicSyncAction(void *addr, uint32_t offset, uint32_t len)
{
    PE_panic_save_context_t context = {
        .psc_buffer = addr,
        .psc_offset = offset,
        .psc_length = len
    };

    // Don't allow nested calls of panic actions
    if (!gActionQueues[kQueuePanic].next) return (kIOReturnNotReady);
    return (iocpu_run_platform_actions(&gActionQueues[kQueuePanic], 0, 0U-1,
				    (void *)(uintptr_t)(kPEPanicSync), &context, NULL, FALSE));

}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static kern_return_t 
IOServicePlatformAction(void * refcon0, void * refcon1, uint32_t priority,
			  void * param1, void * param2, void * param3,
			  const char * service_name)
{
    IOReturn	     ret;
    IOService *      service  = (IOService *)      refcon0;
    const OSSymbol * function = (const OSSymbol *) refcon1;

    kprintf("%s -> %s\n", function->getCStringNoCopy(), service_name);

    ret = service->callPlatformFunction(function, false, 
					 (void *)(uintptr_t) priority, param1, param2, param3);

    return (ret);
}

static void
IOInstallServicePlatformAction(IOService * service, uint32_t qidx)
{
    iocpu_platform_action_entry_t * entry;
    OSNumber *       num;
    uint32_t         priority;
    const OSSymbol * key = gActionSymbols[qidx]; 
    queue_head_t *   queue = &gActionQueues[qidx];
    bool             reverse;
    bool             uniq;

    num = OSDynamicCast(OSNumber, service->getProperty(key));
    if (!num) return;

    reverse = false;
    uniq    = false;
    switch (qidx)
    {
	case kQueueWake:
	case kQueueActive:
	    reverse = true;
	    break;
	case kQueueHaltRestart:
	case kQueuePanic:
	    uniq = true;
	    break;
    }
    if (uniq)
    {
	queue_iterate(queue, entry, iocpu_platform_action_entry_t *, link)
	{
	    if (service == entry->refcon0) return;
	}
    }

    entry = IONew(iocpu_platform_action_entry_t, 1);
    entry->action = &IOServicePlatformAction;
    entry->name = service->getName();
    priority = num->unsigned32BitValue();
    if (reverse)
	entry->priority = -priority;
    else
	entry->priority = priority;
    entry->refcon0 = service;
    entry->refcon1 = (void *) key;
    entry->callout_in_progress = FALSE;

    iocpu_add_platform_action(queue, entry);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOCPUInitialize(void)
{
    gIOCPUsLock = IOLockAlloc();
    gIOCPUs     = OSArray::withCapacity(1);

    for (uint32_t qidx = kQueueSleep; qidx < kQueueCount; qidx++)
    {
	queue_init(&gActionQueues[qidx]);
    }

    gIOCPUStateKey = OSSymbol::withCStringNoCopy("IOCPUState");

    gIOCPUStateNames[kIOCPUStateUnregistered] =
      OSString::withCStringNoCopy("Unregistered");
    gIOCPUStateNames[kIOCPUStateUninitalized] =
      OSString::withCStringNoCopy("Uninitalized");
    gIOCPUStateNames[kIOCPUStateStopped] =
      OSString::withCStringNoCopy("Stopped");
    gIOCPUStateNames[kIOCPUStateRunning] =
      OSString::withCStringNoCopy("Running");

    gIOPlatformSleepActionKey	     = gActionSymbols[kQueueSleep]
    	= OSSymbol::withCStringNoCopy(kIOPlatformSleepActionKey);
    gIOPlatformWakeActionKey	     = gActionSymbols[kQueueWake]
    	= OSSymbol::withCStringNoCopy(kIOPlatformWakeActionKey);
    gIOPlatformQuiesceActionKey	     = gActionSymbols[kQueueQuiesce]
    	= OSSymbol::withCStringNoCopy(kIOPlatformQuiesceActionKey);
    gIOPlatformActiveActionKey	     = gActionSymbols[kQueueActive]
    	= OSSymbol::withCStringNoCopy(kIOPlatformActiveActionKey);
    gIOPlatformHaltRestartActionKey  = gActionSymbols[kQueueHaltRestart]
    	= OSSymbol::withCStringNoCopy(kIOPlatformHaltRestartActionKey);
    gIOPlatformPanicActionKey = gActionSymbols[kQueuePanic]
    	= OSSymbol::withCStringNoCopy(kIOPlatformPanicActionKey);
}

IOReturn
IOInstallServicePlatformActions(IOService * service)
{
    IOLockLock(gIOCPUsLock);

    IOInstallServicePlatformAction(service, kQueueHaltRestart);
    IOInstallServicePlatformAction(service, kQueuePanic);

    IOLockUnlock(gIOCPUsLock);

    return (kIOReturnSuccess);
}

IOReturn
IORemoveServicePlatformActions(IOService * service)
{
    iocpu_platform_action_entry_t * entry;
    iocpu_platform_action_entry_t * next;

    IOLockLock(gIOCPUsLock);

    for (uint32_t qidx = kQueueSleep; qidx < kQueueCount; qidx++)
    {
	next = (typeof(entry)) queue_first(&gActionQueues[qidx]);
	while (!queue_end(&gActionQueues[qidx], &next->link))
	{
	    entry = next;
	    next = (typeof(entry)) queue_next(&entry->link);
	    if (service == entry->refcon0)
	    {
		iocpu_remove_platform_action(entry);
		IODelete(entry, iocpu_platform_action_entry_t, 1);
	    }
	}
    }

    IOLockUnlock(gIOCPUsLock);

    return (kIOReturnSuccess);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t PE_cpu_start(cpu_id_t target,
			   vm_offset_t start_paddr, vm_offset_t arg_paddr)
{
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);
  
  if (targetCPU == 0) return KERN_FAILURE;
  return targetCPU->startCPU(start_paddr, arg_paddr);
}

void PE_cpu_halt(cpu_id_t target)
{
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);
  
  if (targetCPU) targetCPU->haltCPU();
}

void PE_cpu_signal(cpu_id_t source, cpu_id_t target)
{
  IOCPU *sourceCPU = OSDynamicCast(IOCPU, (OSObject *)source);
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);
  
  if (sourceCPU && targetCPU) sourceCPU->signalCPU(targetCPU);
}

void PE_cpu_signal_deferred(cpu_id_t source, cpu_id_t target)
{
  IOCPU *sourceCPU = OSDynamicCast(IOCPU, (OSObject *)source);
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);

  if (sourceCPU && targetCPU) sourceCPU->signalCPUDeferred(targetCPU);
}

void PE_cpu_signal_cancel(cpu_id_t source, cpu_id_t target)
{
  IOCPU *sourceCPU = OSDynamicCast(IOCPU, (OSObject *)source);
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);

  if (sourceCPU && targetCPU) sourceCPU->signalCPUCancel(targetCPU);
}

void PE_cpu_machine_init(cpu_id_t target, boolean_t bootb)
{
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);
  
  if (targetCPU) {
   targetCPU->initCPU(bootb);
#if defined(__arm__) || defined(__arm64__)
   if (!bootb && (targetCPU->getCPUNumber() == (UInt32)master_cpu)) ml_set_is_quiescing(false);
#endif /* defined(__arm__) || defined(__arm64__) */
  }
}

void PE_cpu_machine_quiesce(cpu_id_t target)
{
  IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);
  if (targetCPU) {
#if defined(__arm__) || defined(__arm64__)
      if (targetCPU->getCPUNumber() == (UInt32)master_cpu) ml_set_is_quiescing(true);
#endif /* defined(__arm__) || defined(__arm64__) */
      targetCPU->quiesceCPU();
  }
}

#if defined(__arm__) || defined(__arm64__)
static perfmon_interrupt_handler_func pmi_handler = 0;

kern_return_t PE_cpu_perfmon_interrupt_install_handler(perfmon_interrupt_handler_func handler)
{
    pmi_handler = handler;

    return KERN_SUCCESS;
}

void PE_cpu_perfmon_interrupt_enable(cpu_id_t target, boolean_t enable)
{
    IOCPU *targetCPU = OSDynamicCast(IOCPU, (OSObject *)target);

    if (targetCPU) {
        if (enable) {
	    targetCPU->getProvider()->registerInterrupt(1, targetCPU, (IOInterruptAction)pmi_handler, 0);
	    targetCPU->getProvider()->enableInterrupt(1);
	} else {
	    targetCPU->getProvider()->disableInterrupt(1);
	}
    }
}
#endif

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

void IOCPUSleepKernel(void)
{
    long cnt, numCPUs;
    IOCPU *target;
    IOCPU *bootCPU = NULL;
    IOPMrootDomain  *rootDomain = IOService::getPMRootDomain();

    kprintf("IOCPUSleepKernel\n");

    IORegistryIterator * iter;
    OSOrderedSet *       all;
    IOService *          service;

    rootDomain->tracePoint( kIOPMTracePointSleepPlatformActions );

    iter = IORegistryIterator::iterateOver( gIOServicePlane,
					    kIORegistryIterateRecursively );
    if( iter)
    {
	all = 0;
	do 
	{
	    if (all)
		all->release();
	    all = iter->iterateAll();
	}
	while (!iter->isValid());
	iter->release();

	if (all)
	{
	    while((service = (IOService *) all->getFirstObject()))
	    {
		for (uint32_t qidx = kQueueSleep; qidx <= kQueueActive; qidx++)
		{
		    IOInstallServicePlatformAction(service, qidx);
		}
		all->removeObject(service);
	    }
	    all->release();
	}	
    }

    iocpu_run_platform_actions(&gActionQueues[kQueueSleep], 0, 0U-1,
				NULL, NULL, NULL, TRUE);

    rootDomain->tracePoint( kIOPMTracePointSleepCPUs );

    numCPUs = gIOCPUs->getCount();
    // Sleep the CPUs.
    cnt = numCPUs;
    while (cnt--) 
    {
        target = OSDynamicCast(IOCPU, gIOCPUs->getObject(cnt));
        
        // We make certain that the bootCPU is the last to sleep
        // We'll skip it for now, and halt it after finishing the
        // non-boot CPU's.
        if (target->getCPUNumber() == (UInt32)master_cpu) 
        {
            bootCPU = target;
        } else if (target->getCPUState() == kIOCPUStateRunning)
        {
	  target->haltCPU();
        }
    }

    assert(bootCPU != NULL);
    assert(cpu_number() == master_cpu);

    console_suspend();

    rootDomain->tracePoint( kIOPMTracePointSleepPlatformDriver );

    // Now sleep the boot CPU.
    bootCPU->haltCPU();

    rootDomain->tracePoint( kIOPMTracePointWakePlatformActions );

    console_resume();

    iocpu_run_platform_actions(&gActionQueues[kQueueWake], 0, 0U-1,
				    NULL, NULL, NULL, TRUE);

    iocpu_platform_action_entry_t * entry;
    for (uint32_t qidx = kQueueSleep; qidx <= kQueueActive; qidx++)
    {
	while (!(queue_empty(&gActionQueues[qidx])))
	{
	    entry = (typeof(entry)) queue_first(&gActionQueues[qidx]);
	    iocpu_remove_platform_action(entry);
	    IODelete(entry, iocpu_platform_action_entry_t, 1);
	}
    }

    rootDomain->tracePoint( kIOPMTracePointWakeCPUs );

    // Wake the other CPUs.
    for (cnt = 0; cnt < numCPUs; cnt++) 
    {
        target = OSDynamicCast(IOCPU, gIOCPUs->getObject(cnt));

        // Skip the already-woken boot CPU.
        if (target->getCPUNumber() != (UInt32)master_cpu) {
            if (target->getCPUState() == kIOCPUStateRunning)
                panic("Spurious wakeup of cpu %u", (unsigned int)(target->getCPUNumber()));		
 
            if (target->getCPUState() == kIOCPUStateStopped)
                processor_start(target->getMachProcessor());
        }
    }
}

bool IOCPU::start(IOService *provider)
{
  OSData *busFrequency, *cpuFrequency, *timebaseFrequency;
  
  if (!super::start(provider)) return false;
  
  _cpuGroup = gIOCPUs;
  cpuNub = provider;
  
  IOLockLock(gIOCPUsLock);
  gIOCPUs->setObject(this);
  IOLockUnlock(gIOCPUsLock);

  // Correct the bus, cpu and timebase frequencies in the device tree.
  if (gPEClockFrequencyInfo.bus_frequency_hz < 0x100000000ULL) {
    busFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.bus_clock_rate_hz, 4);
  } else {
    busFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.bus_frequency_hz, 8);
  }
  provider->setProperty("bus-frequency", busFrequency);
  busFrequency->release();
    
  if (gPEClockFrequencyInfo.cpu_frequency_hz < 0x100000000ULL) {
    cpuFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.cpu_clock_rate_hz, 4);
  } else {
    cpuFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.cpu_frequency_hz, 8);
  }
  provider->setProperty("clock-frequency", cpuFrequency);
  cpuFrequency->release();
  
  timebaseFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.timebase_frequency_hz, 4);
  provider->setProperty("timebase-frequency", timebaseFrequency);
  timebaseFrequency->release();
  
  super::setProperty("IOCPUID", getRegistryEntryID(), sizeof(uint64_t)*8);
  
  setCPUNumber(0);
  setCPUState(kIOCPUStateUnregistered);
  
  return true;
}

OSObject *IOCPU::getProperty(const OSSymbol *aKey) const
{
  if (aKey == gIOCPUStateKey) return gIOCPUStateNames[_cpuState];
  
  return super::getProperty(aKey);
}

bool IOCPU::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
  if (aKey == gIOCPUStateKey) {
    return false;
  }

  return super::setProperty(aKey, anObject);
}

bool IOCPU::serializeProperties(OSSerialize *serialize) const
{
	bool result;
	OSDictionary *dict = dictionaryWithProperties();
	if (!dict) return false;
	dict->setObject(gIOCPUStateKey, gIOCPUStateNames[_cpuState]);
	result = dict->serialize(serialize);
	dict->release();  
	return result;
}

IOReturn IOCPU::setProperties(OSObject *properties)
{
  OSDictionary *dict = OSDynamicCast(OSDictionary, properties);
  OSString     *stateStr;
  IOReturn     result;
  
  if (dict == 0) return kIOReturnUnsupported;
  
  stateStr = OSDynamicCast(OSString, dict->getObject(gIOCPUStateKey));
  if (stateStr != 0) {
    result = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
    if (result != kIOReturnSuccess) return result;
    
    if (setProperty(gIOCPUStateKey, stateStr)) return kIOReturnSuccess;
    
    return kIOReturnUnsupported;
  }
  
  return kIOReturnUnsupported;
}

void IOCPU::signalCPU(IOCPU */*target*/)
{
}

void IOCPU::signalCPUDeferred(IOCPU *target)
{
  // Our CPU may not support deferred IPIs,
  // so send a regular IPI by default
  signalCPU(target);
}

void IOCPU::signalCPUCancel(IOCPU */*target*/)
{
  // Meant to cancel signals sent by
  // signalCPUDeferred; unsupported
  // by default
}

void IOCPU::enableCPUTimeBase(bool /*enable*/)
{
}

UInt32 IOCPU::getCPUNumber(void)
{
  return _cpuNumber;
}

void IOCPU::setCPUNumber(UInt32 cpuNumber)
{
  _cpuNumber = cpuNumber;
  super::setProperty("IOCPUNumber", _cpuNumber, 32);
}

UInt32 IOCPU::getCPUState(void)
{
  return _cpuState;
}

void IOCPU::setCPUState(UInt32 cpuState)
{
  if (cpuState < kIOCPUStateCount) {
    _cpuState = cpuState;
  }
}

OSArray *IOCPU::getCPUGroup(void)
{
  return _cpuGroup;
}

UInt32 IOCPU::getCPUGroupSize(void)
{
  return _cpuGroup->getCount();
}

processor_t IOCPU::getMachProcessor(void)
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

IOReturn IOCPUInterruptController::initCPUInterruptController(int sources)
{
	return initCPUInterruptController(sources, sources);
}

IOReturn IOCPUInterruptController::initCPUInterruptController(int sources, int cpus)
{
  int cnt;
  
  if (!super::init()) return kIOReturnInvalid;

  numSources = sources;
  numCPUs = cpus;

  vectors = (IOInterruptVector *)IOMalloc(numSources * sizeof(IOInterruptVector));
  if (vectors == 0) return kIOReturnNoMemory;
  bzero(vectors, numSources * sizeof(IOInterruptVector));

  // Allocate a lock for each vector
  for (cnt = 0; cnt < numSources; cnt++) {
    vectors[cnt].interruptLock = IOLockAlloc();
    if (vectors[cnt].interruptLock == NULL) {
      for (cnt = 0; cnt < numSources; cnt++) {
	if (vectors[cnt].interruptLock != NULL)
	  IOLockFree(vectors[cnt].interruptLock);
      }
      return kIOReturnNoResources;
    }
  }
  
  ml_init_max_cpus(numSources);

#if KPERF
  /*
   * kperf allocates based on the number of CPUs and requires them to all be
   * accounted for.
   */
  boolean_t found_kperf = FALSE;
  char kperf_config_str[64];
  found_kperf = PE_parse_boot_arg_str("kperf", kperf_config_str, sizeof(kperf_config_str));
  if (found_kperf && kperf_config_str[0] != '\0') {
    kperf_kernel_configure(kperf_config_str);
  }
#endif
  
  return kIOReturnSuccess;
}

void IOCPUInterruptController::registerCPUInterruptController(void)
{
  registerService();
  
  getPlatform()->registerInterruptController(gPlatformInterruptControllerName,
					     this);
}

void IOCPUInterruptController::setCPUInterruptProperties(IOService *service)
{
  int          cnt;
  OSArray      *controller;
  OSArray      *specifier;
  OSData       *tmpData;
  long         tmpLong;
  
  if ((service->getProperty(gIOInterruptControllersKey) != 0) &&
      (service->getProperty(gIOInterruptSpecifiersKey) != 0))
    return;
  
  // Create the interrupt specifer array.
  specifier = OSArray::withCapacity(numSources);
  for (cnt = 0; cnt < numSources; cnt++) {
    tmpLong = cnt;
    tmpData = OSData::withBytes(&tmpLong, sizeof(tmpLong));
    specifier->setObject(tmpData);
    tmpData->release();
  };
  
  // Create the interrupt controller array.
  controller = OSArray::withCapacity(numSources);
  for (cnt = 0; cnt < numSources; cnt++) {
    controller->setObject(gPlatformInterruptControllerName);
  }
  
  // Put the two arrays into the property table.
  service->setProperty(gIOInterruptControllersKey, controller);
  service->setProperty(gIOInterruptSpecifiersKey, specifier);
  controller->release();
  specifier->release();
}

void IOCPUInterruptController::enableCPUInterrupt(IOCPU *cpu)
{
	IOInterruptHandler handler = OSMemberFunctionCast(
		IOInterruptHandler, this, &IOCPUInterruptController::handleInterrupt);

	assert(numCPUs > 0);

	ml_install_interrupt_handler(cpu, cpu->getCPUNumber(), this, handler, 0);

	IOTakeLock(vectors[0].interruptLock);
	++enabledCPUs;

	if (enabledCPUs == numCPUs) {
		IOService::cpusRunning();
		thread_wakeup(this);
  	}
	IOUnlock(vectors[0].interruptLock);
}

IOReturn IOCPUInterruptController::registerInterrupt(IOService *nub,
						     int source,
						     void *target,
						     IOInterruptHandler handler,
						     void *refCon)
{
  IOInterruptVector *vector;

  if (source >= numSources) return kIOReturnNoResources;

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
  } else
    IOUnlock(vectors[0].interruptLock);

  return kIOReturnSuccess;
}

IOReturn IOCPUInterruptController::getInterruptType(IOService */*nub*/,
						    int /*source*/,
						    int *interruptType)
{
  if (interruptType == 0) return kIOReturnBadArgument;
  
  *interruptType = kIOInterruptTypeLevel;
  
  return kIOReturnSuccess;
}

IOReturn IOCPUInterruptController::enableInterrupt(IOService */*nub*/,
						   int /*source*/)
{
//  ml_set_interrupts_enabled(true);
  return kIOReturnSuccess;
}

IOReturn IOCPUInterruptController::disableInterrupt(IOService */*nub*/,
						    int /*source*/)
{
//  ml_set_interrupts_enabled(false);
  return kIOReturnSuccess;
}

IOReturn IOCPUInterruptController::causeInterrupt(IOService */*nub*/,
						  int /*source*/)
{
  ml_cause_interrupt();
  return kIOReturnSuccess;
}

IOReturn IOCPUInterruptController::handleInterrupt(void */*refCon*/,
						   IOService */*nub*/,
						   int source)
{
  IOInterruptVector *vector;
  
  vector = &vectors[source];
  
  if (!vector->interruptRegistered) return kIOReturnInvalid;
  
  vector->handler(vector->target, vector->refCon,
		  vector->nub, vector->source);
  
  return kIOReturnSuccess;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
