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

bool IOCommandGate::init(OSObject *inOwner, Action inAction = 0)
{
    return super::init(inOwner, (IOEventSource::Action) inAction);
}

IOCommandGate *
IOCommandGate::commandGate(OSObject *inOwner, Action inAction = 0)
{
    IOCommandGate *me = new IOCommandGate;

    if (me && !me->init(inOwner, inAction)) {
        me->free();
        return 0;
    }

    return me;
}

IOReturn IOCommandGate::runCommand(void *arg0 = 0, void *arg1 = 0,
                                   void *arg2 = 0, void *arg3 = 0)
{
    IOReturn res;

    if (!enabled)
        return kIOReturnNotPermitted;

    if (!action)
        return kIOReturnNoResources;

    // closeGate is recursive so don't worry if we already hold the lock.
    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) action, (unsigned int) owner);

    closeGate();
    res = (*(Action) action)(owner, arg0, arg1, arg2, arg3);
    openGate();

    return res;
}

IOReturn IOCommandGate::runAction(Action inAction,
                                  void *arg0 = 0, void *arg1 = 0,
                                  void *arg2 = 0, void *arg3 = 0)
{
    IOReturn res;

    if (!enabled)
        return kIOReturnNotPermitted;

    if (!inAction)
        return kIOReturnBadArgument;

    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) inAction, (unsigned int) owner);

    // closeGate is recursive so don't worry if we already hold the lock.
    closeGate();
    res = (*inAction)(owner, arg0, arg1, arg2, arg3);
    openGate();

    return res;
}

IOReturn IOCommandGate::attemptCommand(void *arg0 = 0, void *arg1 = 0,
                                       void *arg2 = 0, void *arg3 = 0)
{
    IOReturn res;

    if (!enabled)
        return kIOReturnNotPermitted;

    if (!action)
        return kIOReturnNoResources;

    // Try to hold the lock if can't get return immediately.
    if (!tryCloseGate())
        return kIOReturnCannotLock;

    // closeGate is recursive so don't worry if we already hold the lock.
    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) action, (unsigned int) owner);

    res = (*(Action) action)(owner, arg0, arg1, arg2, arg3);
    openGate();

    return res;
}

IOReturn IOCommandGate::attemptAction(Action inAction,
                                      void *arg0 = 0, void *arg1 = 0,
                                      void *arg2 = 0, void *arg3 = 0)
{
    IOReturn res;

    if (!enabled)
        return kIOReturnNotPermitted;

    if (!inAction)
        return kIOReturnBadArgument;

    // Try to close the gate if can't get return immediately.
    if (!tryCloseGate())
        return kIOReturnCannotLock;

    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) inAction, (unsigned int) owner);

    res = (*inAction)(owner, arg0, arg1, arg2, arg3);
    openGate();

    return res;
}

IOReturn IOCommandGate::commandSleep(void *event, UInt32 interruptible)
{
    IOReturn ret;

    if (!workLoop->inGate())
        return kIOReturnNotPermitted;

    return sleepGate(event, interruptible);
}

void IOCommandGate::commandWakeup(void *event, bool oneThread)
{
    wakeupGate(event, oneThread);
}
