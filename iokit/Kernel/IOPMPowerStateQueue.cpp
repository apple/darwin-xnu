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
#include "IOKit/IOLocks.h"
#undef super
#define super IOEventSource
OSDefineMetaClassAndStructors(IOPMPowerStateQueue, IOEventSource);

#ifndef __ppc__ /* ppc does this right and doesn't need these routines */
static
void *	OSDequeueAtomic(void * volatile * inList, SInt32 inOffset)
{	
	/* The _pointer_ is volatile, not the listhead itself */
	void * volatile	oldListHead;
	void * volatile	newListHead;

	do {
		oldListHead = *inList;
		if (oldListHead == NULL) {
			break;
		}
		
		newListHead = *(void * volatile *) (((char *) oldListHead) + inOffset);
	} while (! OSCompareAndSwap((UInt32)oldListHead,
					(UInt32)newListHead, (volatile UInt32 *)inList));
	return oldListHead;
}

static
void	OSEnqueueAtomic(void * volatile * inList, void * inNewLink, SInt32 inOffset)
{
	/* The _pointer_ is volatile, not the listhead itself */
	void *	volatile oldListHead;
	void *	volatile newListHead = inNewLink;
	void * volatile *	newLinkNextPtr = (void * volatile *) (((char *) inNewLink) + inOffset);

	do {
		oldListHead = *inList;
		*newLinkNextPtr = oldListHead;
	} while (! OSCompareAndSwap((UInt32)oldListHead, (UInt32)newListHead,
					(volatile UInt32 *)inList));
}
#endif /* ! __ppc__ */


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
#ifndef __ppc__
    if (!(tmpLock = IOLockAlloc()))  panic("IOPMPowerStateQueue::init can't alloc lock");
#endif
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
#ifndef __ppc__
    IOLockLock(tmpLock);
#endif
    OSEnqueueAtomic((void **)&changes, (void *)new_one, 0);
#ifndef __ppc__
    IOLockUnlock(tmpLock);
#endif
    signalWorkAvailable();

    return true;
}

bool IOPMPowerStateQueue::featureChangeOccurred(
    uint32_t inState, 
    IOService *inTarget)
{
    PowerChangeEntry             *new_one = NULL;

    new_one = (PowerChangeEntry *)IOMalloc(sizeof(PowerChangeEntry));
    if(!new_one) return false;
    
    new_one->actionType = IOPMPowerStateQueue::kPMFeatureChange;
    new_one->state = inState;
    new_one->target = inTarget;
    
    // Change to queue
#ifdef __i386__
    IOLockLock(tmpLock);
#endif
    OSEnqueueAtomic((void **)&changes, (void *)new_one, 0);
#ifdef __i386__
    IOLockUnlock(tmpLock);
#endif
    signalWorkAvailable();

    return true;
}


// checkForWork() is called in a gated context
bool IOPMPowerStateQueue::checkForWork()
{
    PowerChangeEntry            *theNode;
    uint32_t                    theState;
    IOService                   *theTarget;
    uint16_t                    theAction;
    
    // Dequeue and process the state change request
#ifndef __ppc__
    IOLockLock(tmpLock);
#endif
    if((theNode = (PowerChangeEntry *)OSDequeueAtomic((void **)&changes, 0)))
    {
#ifndef __ppc__
      IOLockUnlock(tmpLock);
#endif
        theState = theNode->state;
        theTarget = theNode->target;
        theAction = theNode->actionType;
        IOFree((void *)theNode, sizeof(PowerChangeEntry));
        
        switch (theAction)
        {
            case kUnIdle:
                theTarget->command_received((void *)theState, 0, 0, 0);
                break;
                
            case kPMFeatureChange:
                theTarget->messageClients(theState, theTarget);
                break;
        }
    }
#ifndef __ppc__
    else {
      IOLockUnlock(tmpLock);
    }
#endif
    // Return true if there's more work to be done
    if(changes) return true;
    else return false;
}
