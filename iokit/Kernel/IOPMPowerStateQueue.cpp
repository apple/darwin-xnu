/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
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
 
#include "IOPMPowerStateQueue.h"

#define super IOEventSource
OSDefineMetaClassAndStructors( IOPMPowerStateQueue, IOEventSource )

IOPMPowerStateQueue * IOPMPowerStateQueue::PMPowerStateQueue(
    OSObject * inOwner, Action inAction )
{
    IOPMPowerStateQueue * me = new IOPMPowerStateQueue;

    if (me && !me->init(inOwner, inAction))
    {
        me->release();
        return NULL;
    }

    return me;
}

bool IOPMPowerStateQueue::init( OSObject * inOwner, Action inAction )
{
    if (!inAction || !(super::init(inOwner, inAction)))
        return false;

    queue_init( &queueHead );

    queueLock = IOLockAlloc();
    if (!queueLock)
        return false;

    return true;
}

bool IOPMPowerStateQueue::submitPowerEvent(
     uint32_t eventType,
     void *   arg0,
     uint64_t arg1 )
{
    PowerEventEntry * entry;

    entry = IONew(PowerEventEntry, 1);
    if (!entry)
        return false;

    entry->eventType = eventType;
    entry->arg0 = arg0;
    entry->arg1 = arg1;

    IOLockLock(queueLock);
    queue_enter(&queueHead, entry, PowerEventEntry *, chain);
    IOLockUnlock(queueLock);
    signalWorkAvailable();

    return true;
}

bool IOPMPowerStateQueue::checkForWork( void )
{
    IOPMPowerStateQueueAction queueAction = (IOPMPowerStateQueueAction) action;
    PowerEventEntry * entry;

	IOLockLock(queueLock);
	while (!queue_empty(&queueHead))
	{
		queue_remove_first(&queueHead, entry, PowerEventEntry *, chain);		
		IOLockUnlock(queueLock);

        (*queueAction)(owner, entry->eventType, entry->arg0, entry->arg1);        
        IODelete(entry, PowerEventEntry, 1);

        IOLockLock(queueLock);
	}
	IOLockUnlock(queueLock);

    return false;
}
