/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
 
#include "IOPMPowerStateQueue.h"
#undef super
#define super IOEventSource
OSDefineMetaClassAndStructors(IOPMPowerStateQueue, IOEventSource);

IOPMPowerStateQueue *IOPMPowerStateQueue::PMPowerStateQueue(OSObject *inOwner)
{
    IOPMPowerStateQueue     *me = new IOPMPowerStateQueue;

    if(me && !me->init(inOwner, 0) )
    {
        me->release();
        return NULL;
    }

    return me;
}

bool IOPMPowerStateQueue::init(OSObject *owner, Action action)
{
    if(!(super::init(owner, (IOEventSource::Action) action))) return false;

    // Queue of powerstate changes
    changes = NULL;

    return true;
}


bool IOPMPowerStateQueue::unIdleOccurred(IOService *inTarget, unsigned long inState)
{
    PowerChangeEntry             *new_one = NULL;

    new_one = (PowerChangeEntry *)IOMalloc(sizeof(PowerChangeEntry));
    if(!new_one) return false;
    
    new_one->actionType = IOPMPowerStateQueue::kUnIdle;
    new_one->state = inState;
    new_one->target = inTarget;
    
    // Change to queue
    OSEnqueueAtomic((void **)&changes, (void *)new_one, 0);
    
    signalWorkAvailable();

    return true;
}

// checkForWork() is called in a gated context
bool IOPMPowerStateQueue::checkForWork()
{
    PowerChangeEntry            *theNode;
    int                         theState;
    IOService                   *theTarget;
    UInt16                      theAction;
    
    // Dequeue and process the state change request
    if((theNode = (PowerChangeEntry *)OSDequeueAtomic((void **)&changes, 0)))
    {
        theState = theNode->state;
        theTarget = theNode->target;
        theAction = theNode->actionType;
        IOFree((void *)theNode, sizeof(PowerChangeEntry));
        
        switch (theAction)
        {
            case kUnIdle:
                theTarget->command_received(theState, 0, 0, 0);
                break;
        }
    }

    // Return true if there's more work to be done
    if(changes) return true;
    else return false;
}
