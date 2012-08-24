/*
 * Copyright (c) 1998-2000, 2009-2010 Apple Inc. All rights reserved.
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
#include <libkern/OSDebug.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOKitDebug.h>

#define super IOEventSource

OSDefineMetaClassAndStructors(IOCommandGate, IOEventSource)
#if __LP64__
OSMetaClassDefineReservedUnused(IOCommandGate, 0);
#else
OSMetaClassDefineReservedUsed(IOCommandGate, 0);
#endif
OSMetaClassDefineReservedUnused(IOCommandGate, 1);
OSMetaClassDefineReservedUnused(IOCommandGate, 2);
OSMetaClassDefineReservedUnused(IOCommandGate, 3);
OSMetaClassDefineReservedUnused(IOCommandGate, 4);
OSMetaClassDefineReservedUnused(IOCommandGate, 5);
OSMetaClassDefineReservedUnused(IOCommandGate, 6);
OSMetaClassDefineReservedUnused(IOCommandGate, 7);

#if IOKITSTATS

#define IOStatisticsInitializeCounter() \
do { \
	IOStatistics::setCounterType(IOEventSource::reserved->counter, kIOStatisticsCommandGateCounter); \
} while (0)

#define IOStatisticsActionCall() \
do { \
	IOStatistics::countCommandGateActionCall(IOEventSource::reserved->counter); \
} while (0)

#else

#define IOStatisticsInitializeCounter()
#define IOStatisticsActionCall()

#endif /* IOKITSTATS */

bool IOCommandGate::init(OSObject *inOwner, Action inAction)
{
    bool res = super::init(inOwner, (IOEventSource::Action) inAction);
    if (res) {
        IOStatisticsInitializeCounter();
    }

    return res;
}

IOCommandGate *
IOCommandGate::commandGate(OSObject *inOwner, Action inAction)
{
    IOCommandGate *me = new IOCommandGate;

    if (me && !me->init(inOwner, inAction)) {
        me->release();
        return 0;
    }

    return me;
}

/* virtual */ void IOCommandGate::disable()
{
    if (workLoop && !workLoop->inGate())
	OSReportWithBacktrace("IOCommandGate::disable() called when not gated");

    super::disable();
}

/* virtual */ void IOCommandGate::enable()
{
    if (workLoop) {
	closeGate();
	super::enable();
	wakeupGate(&enabled, /* oneThread */ false); // Unblock sleeping threads
	openGate();
    }
}

/* virtual */ void IOCommandGate::free()
{
    setWorkLoop(0);
    super::free();
}

/* virtual */ void IOCommandGate::setWorkLoop(IOWorkLoop *inWorkLoop)
{
    uintptr_t *sleepersP = (uintptr_t *) &reserved;
    if (!inWorkLoop && workLoop) {		// tearing down
	closeGate();
	*sleepersP |= 1;
	while (*sleepersP >> 1) {
	    thread_wakeup_with_result(&enabled, THREAD_INTERRUPTED);
	    sleepGate(sleepersP, THREAD_UNINT);
	}
	*sleepersP = 0;
	openGate();
    }
    else

    super::setWorkLoop(inWorkLoop);
}

IOReturn IOCommandGate::runCommand(void *arg0, void *arg1,
                                   void *arg2, void *arg3)
{
    return runAction((Action) action, arg0, arg1, arg2, arg3);
}

IOReturn IOCommandGate::attemptCommand(void *arg0, void *arg1,
                                       void *arg2, void *arg3)
{
    return attemptAction((Action) action, arg0, arg1, arg2, arg3);
}

IOReturn IOCommandGate::runAction(Action inAction,
                                  void *arg0, void *arg1,
                                  void *arg2, void *arg3)
{
    if (!inAction)
        return kIOReturnBadArgument;

    // closeGate is recursive needn't worry if we already hold the lock.
    closeGate();

    // If the command gate is disabled and we aren't on the workloop thread
    // itself then sleep until we get enabled.
    IOReturn res;
    if (!workLoop->onThread()) {
	while (!enabled) {
	    uintptr_t *sleepersP = (uintptr_t *) &reserved;

	    *sleepersP += 2;
	    IOReturn res = sleepGate(&enabled, THREAD_ABORTSAFE);
	    *sleepersP -= 2;

	    bool wakeupTearDown = (*sleepersP & 1);
	    if (res || wakeupTearDown) {
		openGate();

		 if (wakeupTearDown)
		     commandWakeup(sleepersP);	// No further resources used

		return kIOReturnAborted;
	    }
	}
    }

    bool trace = ( gIOKitTrace & kIOTraceCommandGates ) ? true : false;
	
	if (trace)
		IOTimeStampStartConstant(IODBG_CMDQ(IOCMDQ_ACTION),
					 VM_KERNEL_UNSLIDE(inAction), (uintptr_t) owner);
	
    IOStatisticsActionCall();
	
    // Must be gated and on the work loop or enabled
    res = (*inAction)(owner, arg0, arg1, arg2, arg3);
	
	if (trace)
		IOTimeStampEndConstant(IODBG_CMDQ(IOCMDQ_ACTION),
				       VM_KERNEL_UNSLIDE(inAction), (uintptr_t) owner);
    
    openGate();
	
    return res;
}

IOReturn IOCommandGate::attemptAction(Action inAction,
                                      void *arg0, void *arg1,
                                      void *arg2, void *arg3)
{
    IOReturn res;

    if (!inAction)
        return kIOReturnBadArgument;

    // Try to close the gate if can't get return immediately.
    if (!tryCloseGate())
        return kIOReturnCannotLock;

    // If the command gate is disabled then sleep until we get a wakeup
    if (!workLoop->onThread() && !enabled)
        res = kIOReturnNotPermitted;
    else {
		
        bool trace = ( gIOKitTrace & kIOTraceCommandGates ) ? true : false;
		
        if (trace)
            IOTimeStampStartConstant(IODBG_CMDQ(IOCMDQ_ACTION),
				     VM_KERNEL_UNSLIDE(inAction), (uintptr_t) owner);
        
        IOStatisticsActionCall();
        
        res = (*inAction)(owner, arg0, arg1, arg2, arg3);
		
        if (trace)
            IOTimeStampEndConstant(IODBG_CMDQ(IOCMDQ_ACTION),
				   VM_KERNEL_UNSLIDE(inAction), (uintptr_t) owner);
    }

    openGate();

    return res;
}

IOReturn IOCommandGate::commandSleep(void *event, UInt32 interruptible)
{
    if (!workLoop->inGate())
        return kIOReturnNotPermitted;

    return sleepGate(event, interruptible);
}

IOReturn IOCommandGate::commandSleep(void *event, AbsoluteTime deadline, UInt32 interruptible)
{
    if (!workLoop->inGate())
        return kIOReturnNotPermitted;

    return sleepGate(event, deadline, interruptible);
}

void IOCommandGate::commandWakeup(void *event, bool oneThread)
{
    wakeupGate(event, oneThread);
}
