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

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/OSDebug.h>
#include <libkern/c++/OSSharedPtr.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOKitDebug.h>

#define super IOEventSource

OSDefineMetaClassAndStructorsWithZone(IOCommandGate, IOEventSource, ZC_NONE)
#if __LP64__
OSMetaClassDefineReservedUnused(IOCommandGate, 0);
#else
OSMetaClassDefineReservedUsedX86(IOCommandGate, 0);
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

bool
IOCommandGate::init(OSObject *inOwner, Action inAction)
{
	bool res = super::init(inOwner, (IOEventSource::Action) inAction);
	if (res) {
		IOStatisticsInitializeCounter();
	}

	return res;
}

OSSharedPtr<IOCommandGate>
IOCommandGate::commandGate(OSObject *inOwner, Action inAction)
{
	OSSharedPtr<IOCommandGate> me = OSMakeShared<IOCommandGate>();

	if (me && !me->init(inOwner, inAction)) {
		return nullptr;
	}

	return me;
}

/* virtual */ void
IOCommandGate::disable()
{
	if (workLoop && !workLoop->inGate()) {
		OSReportWithBacktrace("IOCommandGate::disable() called when not gated");
	}

	super::disable();
}

/* virtual */ void
IOCommandGate::enable()
{
	if (workLoop) {
		closeGate();
		super::enable();
		wakeupGate(&enabled, /* oneThread */ false); // Unblock sleeping threads
		openGate();
	}
}

/* virtual */ void
IOCommandGate::free()
{
	if (workLoop) {
		setWorkLoop(NULL);
	}
	super::free();
}

enum{
	kSleepersRemoved     = 0x00000001,
	kSleepersWaitEnabled = 0x00000002,
	kSleepersActions     = 0x00000100,
	kSleepersActionsMask = 0xffffff00,
};

/* virtual */ void
IOCommandGate::setWorkLoop(IOWorkLoop *inWorkLoop)
{
	IOWorkLoop * wl;
	uintptr_t  * sleepersP = (uintptr_t *) &reserved;
	bool         defer;

	if (!inWorkLoop && (wl = workLoop)) {           // tearing down
		wl->closeGate();
		*sleepersP |= kSleepersRemoved;
		while (*sleepersP & kSleepersWaitEnabled) {
			thread_wakeup_with_result(&enabled, THREAD_INTERRUPTED);
			sleepGate(sleepersP, THREAD_UNINT);
		}
		*sleepersP &= ~kSleepersWaitEnabled;
		defer = (0 != (kSleepersActionsMask & *sleepersP));
		if (!defer) {
			super::setWorkLoop(NULL);
			*sleepersP &= ~kSleepersRemoved;
		}
		wl->openGate();
		return;
	}

	super::setWorkLoop(inWorkLoop);
}

IOReturn
IOCommandGate::runCommand(void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	return runAction((Action) action, arg0, arg1, arg2, arg3);
}

IOReturn
IOCommandGate::attemptCommand(void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	return attemptAction((Action) action, arg0, arg1, arg2, arg3);
}


static IOReturn
IOCommandGateActionToBlock(OSObject *owner,
    void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	return ((IOEventSource::ActionBlock) arg0)();
}

IOReturn
IOCommandGate::runActionBlock(ActionBlock _action)
{
	return runAction(&IOCommandGateActionToBlock, _action);
}

IOReturn
IOCommandGate::runAction(Action inAction,
    void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	IOWorkLoop * wl;
	uintptr_t  * sleepersP;

	if (!inAction) {
		return kIOReturnBadArgument;
	}
	if (!(wl = workLoop)) {
		return kIOReturnNotReady;
	}

	// closeGate is recursive needn't worry if we already hold the lock.
	wl->closeGate();
	sleepersP = (uintptr_t *) &reserved;

	// If the command gate is disabled and we aren't on the workloop thread
	// itself then sleep until we get enabled.
	IOReturn res;
	if (!wl->onThread()) {
		while (!enabled) {
			IOReturn sleepResult = kIOReturnSuccess;
			if (workLoop) {
				*sleepersP |= kSleepersWaitEnabled;
				sleepResult = wl->sleepGate(&enabled, THREAD_INTERRUPTIBLE);
				*sleepersP &= ~kSleepersWaitEnabled;
			}
			bool wakeupTearDown = (!workLoop || (0 != (*sleepersP & kSleepersRemoved)));
			if ((kIOReturnSuccess != sleepResult) || wakeupTearDown) {
				wl->openGate();

				if (wakeupTearDown) {
					wl->wakeupGate(sleepersP, false); // No further resources used
				}
				return kIOReturnAborted;
			}
		}
	}

	bool trace = (gIOKitTrace & kIOTraceCommandGates) ? true : false;

	if (trace) {
		IOTimeStampStartConstant(IODBG_CMDQ(IOCMDQ_ACTION),
		    VM_KERNEL_ADDRHIDE(inAction), VM_KERNEL_ADDRHIDE(owner));
	}

	IOStatisticsActionCall();

	// Must be gated and on the work loop or enabled

	*sleepersP += kSleepersActions;
	res = (*inAction)(owner, arg0, arg1, arg2, arg3);
	*sleepersP -= kSleepersActions;

	if (trace) {
		IOTimeStampEndConstant(IODBG_CMDQ(IOCMDQ_ACTION),
		    VM_KERNEL_ADDRHIDE(inAction), VM_KERNEL_ADDRHIDE(owner));
	}

	if (kSleepersRemoved == ((kSleepersActionsMask | kSleepersRemoved) & *sleepersP)) {
		// no actions outstanding
		*sleepersP &= ~kSleepersRemoved;
		super::setWorkLoop(NULL);
	}

	wl->openGate();

	return res;
}

IOReturn
IOCommandGate::attemptAction(Action inAction,
    void *arg0, void *arg1,
    void *arg2, void *arg3)
{
	IOReturn res;
	IOWorkLoop * wl;

	if (!inAction) {
		return kIOReturnBadArgument;
	}
	if (!(wl = workLoop)) {
		return kIOReturnNotReady;
	}

	// Try to close the gate if can't get return immediately.
	if (!wl->tryCloseGate()) {
		return kIOReturnCannotLock;
	}

	// If the command gate is disabled then sleep until we get a wakeup
	if (!wl->onThread() && !enabled) {
		res = kIOReturnNotPermitted;
	} else {
		bool trace = (gIOKitTrace & kIOTraceCommandGates) ? true : false;

		if (trace) {
			IOTimeStampStartConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			    VM_KERNEL_ADDRHIDE(inAction), VM_KERNEL_ADDRHIDE(owner));
		}

		IOStatisticsActionCall();

		res = (*inAction)(owner, arg0, arg1, arg2, arg3);

		if (trace) {
			IOTimeStampEndConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			    VM_KERNEL_ADDRHIDE(inAction), VM_KERNEL_ADDRHIDE(owner));
		}
	}

	wl->openGate();

	return res;
}

IOReturn
IOCommandGate::commandSleep(void *event, UInt32 interruptible)
{
	if (!workLoop->inGate()) {
		/* The equivalent of 'msleep' while not holding the mutex is invalid */
		panic("invalid commandSleep while not holding the gate");
	}

	return sleepGate(event, interruptible);
}

IOReturn
IOCommandGate::commandSleep(void *event, AbsoluteTime deadline, UInt32 interruptible)
{
	if (!workLoop->inGate()) {
		/* The equivalent of 'msleep' while not holding the mutex is invalid */
		panic("invalid commandSleep while not holding the gate");
	}

	return sleepGate(event, deadline, interruptible);
}

void
IOCommandGate::commandWakeup(void *event, bool oneThread)
{
	wakeupGate(event, oneThread);
}
