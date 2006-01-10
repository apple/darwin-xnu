/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.

HISTORY
    1998-7-13	Godfrey van der Linden(gvdl)
        Created.
*/
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimeStamp.h>

#define super OSObject

OSDefineMetaClassAndStructors(IOWorkLoop, OSObject);

// Block of unused functions intended for future use
OSMetaClassDefineReservedUsed(IOWorkLoop, 0);

OSMetaClassDefineReservedUnused(IOWorkLoop, 1);
OSMetaClassDefineReservedUnused(IOWorkLoop, 2);
OSMetaClassDefineReservedUnused(IOWorkLoop, 3);
OSMetaClassDefineReservedUnused(IOWorkLoop, 4);
OSMetaClassDefineReservedUnused(IOWorkLoop, 5);
OSMetaClassDefineReservedUnused(IOWorkLoop, 6);
OSMetaClassDefineReservedUnused(IOWorkLoop, 7);

enum IOWorkLoopState { kLoopRestart = 0x1, kLoopTerminate = 0x2 };
static inline void SETP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; *num |= flag; }
static inline void CLRP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; *num &= ~flag; }
static inline bool ISSETP(void *addr, unsigned int flag)
    { unsigned int *num = (unsigned int *) addr; return (*num & flag) != 0; }

#define fFlags loopRestart

bool IOWorkLoop::init()
{
    // The super init and gateLock allocation MUST be done first
    if ( !super::init() )
        return false;

    if ( !(gateLock = IORecursiveLockAlloc()) )
        return false;

    if ( !(workToDoLock = IOSimpleLockAlloc()) )
        return false;

    controlG = IOCommandGate::
	commandGate(this, (IOCommandGate::Action) &IOWorkLoop::_maintRequest);
    if ( !controlG )
        return false;

    IOSimpleLockInit(workToDoLock);
    workToDo = false;

    // Point the controlGate at the workLoop.  Usually addEventSource
    // does this automatically.  The problem is in this case addEventSource
    // uses the control gate and it has to be bootstrapped.
    controlG->setWorkLoop(this);
    if (addEventSource(controlG) != kIOReturnSuccess)
        return false;

    workThread = IOCreateThread((thread_continue_t)threadMainContinuation, this);
    if (!workThread)
        return false;

    return true;
}

IOWorkLoop *
IOWorkLoop::workLoop()
{
    IOWorkLoop *me = new IOWorkLoop;

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
	// in this case disable all of the event source, mark the loop for
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

	// Either we have a partial initialisation to clean up
	// or we the workThread itself is performing hari-kari.
	// either way clean up all of our resources and return.
	
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

void IOWorkLoop::threadMainContinuation(IOWorkLoop *self)
{
	self->threadMain();
}

void IOWorkLoop::threadMain()
{
    CLRP(&fFlags, kLoopRestart);

    for (;;) {
        bool more;
	IOInterruptState is;

    IOTimeWorkS();

        closeGate();
        if (ISSETP(&fFlags, kLoopTerminate))
	    goto exitThread;

        do {
            workToDo = more = false;
            for (IOEventSource *event = eventChain; event; event = event->getNext()) {

            IOTimeClientS();
                more |= event->checkForWork();
            IOTimeClientE();

		if (ISSETP(&fFlags, kLoopTerminate))
		    goto exitThread;
                else if (fFlags & kLoopRestart) {
		    CLRP(&fFlags, kLoopRestart);
                    continue;
                }
            }
        } while (more);

    IOTimeWorkE();

        openGate();

	is = IOSimpleLockLockDisableInterrupt(workToDoLock);
        if ( !ISSETP(&fFlags, kLoopTerminate) && !workToDo) {
	    assert_wait((void *) &workToDo, false);
	    IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);

	    thread_block_parameter((thread_continue_t)threadMainContinuation, this);
	    /* NOTREACHED */
	}

	// At this point we either have work to do or we need
	// to commit suicide.  But no matter 
	// Clear the simple lock and retore the interrupt state
	IOSimpleLockUnlockEnableInterrupt(workToDoLock, is);
	if (workToDo)
	    continue;
	else
	    break;
    }

exitThread:
    workThread = 0;	// Say we don't have a loop and free ourselves
    free();
    IOExitThread();
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
    maintCommandEnum command = (maintCommandEnum) (vm_address_t) inC;
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
