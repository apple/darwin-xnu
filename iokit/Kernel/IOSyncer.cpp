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
/* IOSyncer.cpp created by wgulland on 2000-02-02 */

#include <IOKit/IOLib.h>
#include <IOKit/IOSyncer.h>

OSDefineMetaClassAndStructors(IOSyncer, OSObject)

IOSyncer * IOSyncer::create(bool twoRetains)
{
    IOSyncer * me = new IOSyncer;

    if (me && !me->init(twoRetains)) {
        me->release();
        return 0;
    }

    return me;
}

bool IOSyncer::init(bool twoRetains)
{
    if (!OSObject::init())
        return false;

    if (!(guardLock = IOSimpleLockAlloc()) )
        return false;
	
    IOSimpleLockInit(guardLock);

    if(twoRetains)
	retain();

    fResult = kIOReturnSuccess;

    reinit();

    return true;
}

void IOSyncer::reinit()
{
    IOInterruptState is = IOSimpleLockLockDisableInterrupt(guardLock);
    threadMustStop = true;
    IOSimpleLockUnlockEnableInterrupt(guardLock, is);
}

void IOSyncer::free()
{
    // just in case a thread is blocked here:
    privateSignal();

    if (guardLock != NULL)
       IOSimpleLockFree(guardLock);

    OSObject::free();
}

IOReturn IOSyncer::wait(bool autoRelease = true)
{
    IOInterruptState is = IOSimpleLockLockDisableInterrupt(guardLock);

    if (threadMustStop) {
	assert_wait((void *) &threadMustStop, false);
    	IOSimpleLockUnlockEnableInterrupt(guardLock, is);
        thread_block(THREAD_CONTINUE_NULL);
    }
    else
        IOSimpleLockUnlockEnableInterrupt(guardLock, is);

    IOReturn result = fResult;	// Pick up before auto deleting!

    if(autoRelease)
	release();

    return result;
}

void IOSyncer::signal(IOReturn res = kIOReturnSuccess,
					bool autoRelease = true)
{
    fResult = res;
    privateSignal();
    if(autoRelease)
	release();
}

void IOSyncer::privateSignal()
{
    if (threadMustStop) {
         IOInterruptState is = IOSimpleLockLockDisableInterrupt(guardLock);
         threadMustStop = false;
         thread_wakeup_one((void *) &threadMustStop);
         IOSimpleLockUnlockEnableInterrupt(guardLock, is);
    }
}
