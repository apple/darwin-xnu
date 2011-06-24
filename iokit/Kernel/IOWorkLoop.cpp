/*
 * Copyright (c) 1998-2007 Apple Inc. All rights reserved.
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

#include <pexpert/pexpert.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOKitDebug.h>
#include <libkern/OSDebug.h>

#define super OSObject

OSDefineMetaClassAndStructors(IOWorkLoop, OSObject);

// Block of unused functions intended for future use
#if __LP64__
OSMetaClassDefineReservedUnused(IOWorkLoop, 0);
OSMetaClassDefineReservedUnused(IOWorkLoop, 1);
OSMetaClassDefineReservedUnused(IOWorkLoop, 2);
#else
OSMetaClassDefineReservedUsed(IOWorkLoop, 0);
OSMetaClassDefineReservedUsed(IOWorkLoop, 1);
OSMetaClassDefineReservedUsed(IOWorkLoop, 2);
#endif
OSMetaClassDefineReservedUnused(IOWorkLoop, 3);
OSMetaClassDefineReservedUnused(IOWorkLoop, 4);
OSMetaClassDefineReservedUnused(IOWorkLoop, 5);
OSMetaClassDefineReservedUnused(IOWorkLoop, 6);
OSMetaClassDefineReservedUnused(IOWorkLoop, 7);

enum IOWorkLoopState { kLoopRestart = 0x1, kLoopTerminate = 0x2 };
#ifdef __ppc__
static inline void SETP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; *num |= flag; }
static inline void CLRP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; *num &= ~flag; }
static inline bool ISSETP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; return (*num & flag) != 0; }
#else
static inline void SETP(void *addr, unsigned int flag)
    { unsigned char *num = (unsigned char *) addr; *num |= flag; }
static inline void CLRP(void *addr, unsigned int flag)
    { unsigned char *num = (unsigned char *) addr; *num &= ~flag; }
static inline bool ISSETP(void *addr, unsigned int flag)
    { unsigned char *num = (unsigned char *) addr; return (*num & flag) != 0; }
#endif

#define fFlags loopRestart


bool IOWorkLoop::init()
{
    // The super init and gateLock allocation MUST be done first
    if ( !super::init() )
        return false;
	
    if ( gateLock == NULL ) {
        if ( !( gateLock = IORecursiveLockAlloc()) )
            return false;
    }
	
    if ( workToDoLock == NULL ) {
        if ( !(workToDoLock = IOSimpleLockAlloc()) )
            return false;
        IOSimpleLockInit(workToDoLock);
        workToDo = false;
    }

    if ( controlG == NULL ) {
        controlG = IOCommandGate::commandGate(
            this,
            OSMemberFunctionCast(
                IOCommandGate::Action,
                this,
                &IOWorkLoop::_maintRequest));

        if ( !controlG )
            return false;
        // Point the controlGate at the workLoop.  Usually addEventSource
        // does this automatically.  The problem is in this case addEventSource
        // uses the control gate and it has to be bootstrapped.
        controlG->setWorkLoop(this);
        if (addEventSource(controlG) != kIOReturnSuccess)
            return false;
    }

    if ( workThread == NULL ) {
        thread_continue_t cptr = OSMemberFunctionCast(
            thread_continue_t,
            this,
            &IOWorkLoop::threadMain);
        if (KERN_SUCCESS != kernel_thread_start(cptr, this, &workThread))
            return false;
    }

    return true;
}

IOWorkLoop *
IOWorkLoop::workLoop()
{
    return IOWorkLoop::workLoopWithOptions(0);
}

IOWorkLoop *
IOWorkLoop::workLoopWithOptions(IOOptionBits options)
{
    IOWorkLoop *me = new IOWorkLoop;

    if (me && options) {
	me->reserved = IONew(ExpansionData, 1);
	if (!me->reserved) {
	    me->release();
	    return 0;
	}
	me->reserved->options = options;
    }

    if (me && !me->init()) {
        me->release();
        return 0;
    }

    return me;
}

// Free is called twice:
// First when the atomic retainCount transitions from 1 -> 0
// Secondly when the work loop itself is commiting hari kari
// Hence the each leg of the free must be single threaded.
void IOWorkLoop::free()
{
    if (workThread) {
	IOInterruptState is;

	// If we are here then we must be trying to shut down this work loop
	// in this case disable all of the event source, mark the loop
	// as terminating and wakeup the work thread itself and return
	// Note: we hold the gate across the entire operation mainly for the 
	// benefit of our event sources so we can disable them cleanly.
	closeGate();

	disableAllEventSources();

        is = IOSimpleLockLockDisableInterrupt(workToDoLock);
	SETP(&fFlags, kLoopTerminate);
        thread_wakeup_one((void *) &workToDo);
        IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);

	openGate();
    }
    else /* !workThread */ {
        IOEventSource *event, *next;

        for (event = eventChain; event; event = next) {
            next = event->getNext();
            event->setWorkLoop(0);
            event->setNext(0);
            event->release();
        }
        eventChain = 0;

	// Either we have a partial initialization to clean up
	// or the workThread itself is performing hari-kari.
	// Either way clean up all of our resources and return.
	
	if (controlG) {
	    controlG->release();
	    controlG = 0;
	}

	if (workToDoLock) {
	    IOSimpleLockFree(workToDoLock);
	    workToDoLock = 0;
	}

	if (gateLock) {
	    IORecursiveLockFree(gateLock);
	    gateLock = 0;
	}
	if (reserved) {
	    IODelete(reserved, ExpansionData, 1);
	    reserved = 0;
	}

	super::free();
    }
}

IOReturn IOWorkLoop::addEventSource(IOEventSource *newEvent)
{
    return controlG->runCommand((void *) mAddEvent, (void *) newEvent);
}
    
IOReturn IOWorkLoop::removeEventSource(IOEventSource *toRemove)
{
    return controlG->runCommand((void *) mRemoveEvent, (void *) toRemove);
}

void IOWorkLoop::enableAllEventSources() const
{
    IOEventSource *event;

    for (event = eventChain; event; event = event->getNext())
        event->enable();
}

void IOWorkLoop::disableAllEventSources() const
{
    IOEventSource *event;

    for (event = eventChain; event; event = event->getNext())
        if (event != controlG)	// Don't disable the control gate
            event->disable();
}

void IOWorkLoop::enableAllInterrupts() const
{
    IOEventSource *event;

    for (event = eventChain; event; event = event->getNext())
        if (OSDynamicCast(IOInterruptEventSource, event))
            event->enable();
}

void IOWorkLoop::disableAllInterrupts() const
{
    IOEventSource *event;

    for (event = eventChain; event; event = event->getNext())
        if (OSDynamicCast(IOInterruptEventSource, event))
            event->disable();
}

#if KDEBUG
#define IOTimeClientS()							\
do {									\
    IOTimeStampStart(IODBG_WORKLOOP(IOWL_CLIENT),			\
                     (unsigned int) this, (unsigned int) event);	\
} while(0)

#define IOTimeClientE()							\
do {									\
    IOTimeStampEnd(IODBG_WORKLOOP(IOWL_CLIENT),				\
                   (unsigned int) this, (unsigned int) event);		\
} while(0)

#define IOTimeWorkS()							\
do {									\
    IOTimeStampStart(IODBG_WORKLOOP(IOWL_WORK),	(unsigned int) this);	\
} while(0)

#define IOTimeWorkE()							\
do {									\
    IOTimeStampEnd(IODBG_WORKLOOP(IOWL_WORK),(unsigned int) this);	\
} while(0)

#else /* !KDEBUG */

#define IOTimeClientS()
#define IOTimeClientE()
#define IOTimeWorkS()
#define IOTimeWorkE()

#endif /* KDEBUG */

/* virtual */ bool IOWorkLoop::runEventSources()
{
    bool res = false;
    bool traceWL = (gIOKitTrace & kIOTraceWorkLoops) ? true : false;
    bool traceES = (gIOKitTrace & kIOTraceEventSources) ? true : false;
    
    closeGate();
    if (ISSETP(&fFlags, kLoopTerminate))
	goto abort;

    if (traceWL)
    	IOTimeStampStartConstant(IODBG_WORKLOOP(IOWL_WORK), (uintptr_t) this);
	
    bool more;
    do {
	CLRP(&fFlags, kLoopRestart);
	more = false;
	IOInterruptState is = IOSimpleLockLockDisableInterrupt(workToDoLock);
	workToDo = false;
	IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);
	for (IOEventSource *evnt = eventChain; evnt; evnt = evnt->getNext()) {

		if (traceES)
			IOTimeStampStartConstant(IODBG_WORKLOOP(IOWL_CLIENT), (uintptr_t) this, (uintptr_t) evnt);
			
	    more |= evnt->checkForWork();
			
		if (traceES)
			IOTimeStampEndConstant(IODBG_WORKLOOP(IOWL_CLIENT), (uintptr_t) this, (uintptr_t) evnt);

	    if (ISSETP(&fFlags, kLoopTerminate))
		goto abort;
	    else if (fFlags & kLoopRestart) {
		more = true;
		break;
	    }
	}
    } while (more);

    res = true;
	
    if (traceWL)
    	IOTimeStampEndConstant(IODBG_WORKLOOP(IOWL_WORK), (uintptr_t) this);

abort:
    openGate();
    return res;
}

/* virtual */ void IOWorkLoop::threadMain()
{
restartThread:
    do {
	if ( !runEventSources() )
	    goto exitThread;

	IOInterruptState is = IOSimpleLockLockDisableInterrupt(workToDoLock);
        if ( !ISSETP(&fFlags, kLoopTerminate) && !workToDo) {
	    assert_wait((void *) &workToDo, false);
	    IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);
	    thread_continue_t cptr = NULL;
	    if (!reserved || !(kPreciousStack & reserved->options))
		cptr = OSMemberFunctionCast(
			thread_continue_t, this, &IOWorkLoop::threadMain);
	    thread_block_parameter(cptr, this);
	    goto restartThread;
	    /* NOTREACHED */
	}

	// At this point we either have work to do or we need
	// to commit suicide.  But no matter 
	// Clear the simple lock and retore the interrupt state
	IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);
    } while(workToDo);

exitThread:
	thread_t thread = workThread;
    workThread = 0;	// Say we don't have a loop and free ourselves
    free();

	thread_deallocate(thread);
    (void) thread_terminate(thread);
}

IOThread IOWorkLoop::getThread() const
{
    return workThread;
}

bool IOWorkLoop::onThread() const
{
    return (IOThreadSelf() == workThread);
}

bool IOWorkLoop::inGate() const
{
    return IORecursiveLockHaveLock(gateLock);
}

// Internal APIs used by event sources to control the thread
void IOWorkLoop::signalWorkAvailable()
{
    if (workToDoLock) {
        IOInterruptState is = IOSimpleLockLockDisableInterrupt(workToDoLock);
        workToDo = true;
        thread_wakeup_one((void *) &workToDo);
        IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);
    }
}

void IOWorkLoop::openGate()
{
    IORecursiveLockUnlock(gateLock);
}

void IOWorkLoop::closeGate()
{
    IORecursiveLockLock(gateLock);
}

bool IOWorkLoop::tryCloseGate()
{
    return IORecursiveLockTryLock(gateLock) != 0;
}

int IOWorkLoop::sleepGate(void *event, UInt32 interuptibleType)
{
    return IORecursiveLockSleep(gateLock, event, interuptibleType);
}

int IOWorkLoop::sleepGate(void *event, AbsoluteTime deadline, UInt32 interuptibleType)
{
    return IORecursiveLockSleepDeadline(gateLock, event, deadline, interuptibleType);
}

void IOWorkLoop::wakeupGate(void *event, bool oneThread)
{
    IORecursiveLockWakeup(gateLock, event, oneThread);
}

IOReturn IOWorkLoop::runAction(Action inAction, OSObject *target,
                                  void *arg0, void *arg1,
                                  void *arg2, void *arg3)
{
    IOReturn res;

    // closeGate is recursive so don't worry if we already hold the lock.
    closeGate();
    res = (*inAction)(target, arg0, arg1, arg2, arg3);
    openGate();

    return res;
}

IOReturn IOWorkLoop::_maintRequest(void *inC, void *inD, void *, void *)
{
    maintCommandEnum command = (maintCommandEnum) (uintptr_t) inC;
    IOEventSource *inEvent = (IOEventSource *) inD;
    IOReturn res = kIOReturnSuccess;

    switch (command)
    {
    case mAddEvent:
        if (!inEvent->getWorkLoop()) {
            SETP(&fFlags, kLoopRestart);

            inEvent->retain();
            inEvent->setWorkLoop(this);
            inEvent->setNext(0);
    
            if (!eventChain)
                eventChain = inEvent;
            else {
                IOEventSource *event, *next;
    
                for (event = eventChain; (next = event->getNext()); event = next)
                    ;
                event->setNext(inEvent);
            }
        }
        break;

    case mRemoveEvent:
        if (inEvent->getWorkLoop()) {
            if (eventChain == inEvent)
                eventChain = inEvent->getNext();
            else {
                IOEventSource *event, *next;
    
                event = eventChain;
                while ((next = event->getNext()) && next != inEvent)
                    event = next;
    
                if (!next) {
                    res = kIOReturnBadArgument;
                    break;
                }
                event->setNext(inEvent->getNext());
            }
    
            inEvent->setWorkLoop(0);
            inEvent->setNext(0);
            inEvent->release();
            SETP(&fFlags, kLoopRestart);
        }
        break;

    default:
        return kIOReturnUnsupported;
    }

    return res;
}
