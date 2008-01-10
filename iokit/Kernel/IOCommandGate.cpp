/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#include <libkern/OSDebug.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOTimeStamp.h>

#define super IOEventSource

OSDefineMetaClassAndStructors(IOCommandGate, IOEventSource)
OSMetaClassDefineReservedUnused(IOCommandGate, 0);
OSMetaClassDefineReservedUnused(IOCommandGate, 1);
OSMetaClassDefineReservedUnused(IOCommandGate, 2);
OSMetaClassDefineReservedUnused(IOCommandGate, 3);
OSMetaClassDefineReservedUnused(IOCommandGate, 4);
OSMetaClassDefineReservedUnused(IOCommandGate, 5);
OSMetaClassDefineReservedUnused(IOCommandGate, 6);
OSMetaClassDefineReservedUnused(IOCommandGate, 7);

bool IOCommandGate::checkForWork() { return false; }

bool IOCommandGate::init(OSObject *inOwner, Action inAction)
{
    return super::init(inOwner, (IOEventSource::Action) inAction);
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

    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) inAction, (unsigned int) owner);

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

    // Must be gated and on the work loop or enabled
    res = (*inAction)(owner, arg0, arg1, arg2, arg3);
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
	IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			    (unsigned int) inAction, (unsigned int) owner);

	res = (*inAction)(owner, arg0, arg1, arg2, arg3);
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

void IOCommandGate::commandWakeup(void *event, bool oneThread)
{
    wakeupGate(event, oneThread);
}
