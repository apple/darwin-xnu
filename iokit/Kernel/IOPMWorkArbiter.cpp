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
 
#include "IOPMWorkArbiter.h"
#include "IOKit/IOLocks.h"
#undef super
#define super IOEventSource
OSDefineMetaClassAndStructors(IOPMWorkArbiter, IOEventSource);

/*************************************************************************/
static
void *    _dequeue(void ** inList, SInt32 inOffset)
{
    void *    oldListHead;
    void *    newListHead;

    do {
        oldListHead = *inList;
        if (oldListHead == NULL) {
            break;
        }
        
        newListHead = *(void **) (((char *) oldListHead) + inOffset);
    } while (! OSCompareAndSwap((UInt32)oldListHead,
                    (UInt32)newListHead, (UInt32 *)inList));
    return oldListHead;
}

/*************************************************************************/
static
void    _enqueue(void ** inList, void * inNewLink, SInt32 inOffset)
{
    void *    oldListHead;
    void *    newListHead = inNewLink;
    void **    newLinkNextPtr = (void **) (((char *) inNewLink) + inOffset);

    do {
        oldListHead = *inList;
        *newLinkNextPtr = oldListHead;
    } while (! OSCompareAndSwap((UInt32)oldListHead, (UInt32)newListHead,
                    (UInt32 *)inList));
}

/*************************************************************************/
IOPMWorkArbiter *IOPMWorkArbiter::pmWorkArbiter(
    IOPMrootDomain *inOwner)
{
    IOPMWorkArbiter     *me = new IOPMWorkArbiter;

    if(me && !me->init((OSObject *)inOwner, 0) )
    {
        me->release();
        return NULL;
    }

    return me;
}

/*************************************************************************/
bool IOPMWorkArbiter::init(OSObject *owner, Action action)
{
    if(!(super::init(owner, (IOEventSource::Action) action))) 
        return false;
        
    events = NULL;
    fRootDomain = (IOPMrootDomain *)owner;
    
    if (!(tmpLock = IOLockAlloc())) {
        panic("IOPMWorkArbiter::init can't alloc lock");
    }
    return true;
}

/*************************************************************************/
bool IOPMWorkArbiter::driverAckedOccurred(IOService *inTarget)
{
    PMEventEntry                 *new_one = NULL;

    new_one = (PMEventEntry *)IOMalloc(sizeof(PMEventEntry));
    if(!new_one) return false;
    
    new_one->actionType = IOPMWorkArbiter::kDriverAcked;
    new_one->target = inTarget;
    
    // Change to queue
    IOLockLock(tmpLock);
    _enqueue((void **)&events, (void *)new_one, 0);
    IOLockUnlock(tmpLock);
    signalWorkAvailable();

    return true;
}

/*************************************************************************/
bool IOPMWorkArbiter::allAckedOccurred(IOService *inTarget)  
{
    PMEventEntry                 *new_one = NULL;

    new_one = (PMEventEntry *)IOMalloc(sizeof(PMEventEntry));
    if(!new_one) return false;
    
    new_one->actionType = IOPMWorkArbiter::kAllAcked;
    new_one->target = inTarget;
    
    // Change to queue
    IOLockLock(tmpLock);
    _enqueue((void **)&events, (void *)new_one, 0);
    IOLockUnlock(tmpLock);
    signalWorkAvailable();

    return true;
}

/*************************************************************************/
bool IOPMWorkArbiter::clamshellStateChangeOccurred(uint32_t messageValue)
{
    PMEventEntry                 *new_one = NULL;

    new_one = (PMEventEntry *)IOMalloc(sizeof(PMEventEntry));
    if(!new_one) return false;
    
    new_one->actionType = IOPMWorkArbiter::kRootDomainClamshellChanged;
    new_one->target = (IOService *)fRootDomain;
    new_one->intArgument = messageValue;
    
    IOLockLock(tmpLock);
    _enqueue((void **)&events, (void *)new_one, 0);
    IOLockUnlock(tmpLock);
    signalWorkAvailable();

    return true;
}


/*************************************************************************/
void IOPMWorkArbiter::checkForWorkThreadFunc(void *refcon)
{
    PMEventEntry                *theNode = (PMEventEntry *)refcon;    
    IOService                   *theTarget;
    UInt16                      theAction;

    if(!theNode) return;
    theTarget = theNode->target;
    theAction = theNode->actionType;
    IOFree(theNode, sizeof(PMEventEntry));
    theNode = NULL;

    switch (theAction)
    {
        case kAllAcked:
            theTarget->all_acked_threaded();
            break;

        case kDriverAcked:
            theTarget->driver_acked_threaded();
            break;
    }

}


/*************************************************************************/
// checkForWork() is called in a gated context
bool IOPMWorkArbiter::checkForWork()
{
    PMEventEntry                *theNode;
    IOService                   *theTarget;
    UInt16                      theAction;
    
    // Dequeue and process the state change request
    IOLockLock(tmpLock);
    if((theNode = (PMEventEntry *)_dequeue((void **)&events, 0)))
    {
      IOLockUnlock(tmpLock);
        theTarget = theNode->target;
        theAction = theNode->actionType;
        IOFree((void *)theNode, sizeof(PMEventEntry));

        switch (theAction)
        {
            case kAllAcked:
                theTarget->all_acked_threaded();
                break;

            case kDriverAcked:
                theTarget->driver_acked_threaded();
                break;

            case kRootDomainClamshellChanged:
                theTarget->messageClients(
                                kIOPMMessageClamshellStateChange, 
                                (void *)theNode->intArgument);
                break;
        }
    }
    else {
      IOLockUnlock(tmpLock);
    }
    // Return true if there's more work to be done
    if(events) return true;
    else return false;
}


/*************************************************************************/

/*************************************************************************/

/*************************************************************************/

/*************************************************************************/
/*
#undef super
#define super OSObject

PMWorkerThread *PMWorkerThread::workerThread( IOPMWorkArbiter *inArbiter )
{
    PMWorkerThread *     inst;

    if( !(inst = new PMWorkerThread) )
        goto exit;
    
    if( !inst->init() )
        goto exit;
        
    inst->arbiter = inArbiter;

    if( !(IOCreateThread((IOThreadFunc) &PMWorkerThread::main, inst)) )
        goto exit;

    return inst;

exit:
    if(inst)
        inst->release();

    return NULL;
}

void PMWorkerThread::free( void )
{
    super::free();
}

void PMWorkerThread::main( PMWorkerThread * self )
{
    PMWorkUnit    *job;
    IOService     *who;

    do {
        // Get a new job 
        
        IOTakeLock( gJobsLock );

        if( !(job = (PMWorkUnit *) gJobs->copyNextJob()) )
        {
            IOUnlock( gJobsLock );
            semaphore_wait( gJobsSemaphore );
            IOTakeLock( gJobsLock );
            
            job = (PMWorkUnit *) gJobs->copyNextJob();
        }

        IOUnlock( gJobsLock );

        if(job) 
        {
            who = job->who;
    
            // Do job 
            switch(job->type) 
            {
                case kMatchNubJob:
                    if(who)
                        who->doServiceMatch();
                    break;

                default:
                    break;
            }
        }

    } while( alive );

    self->release();
}

*/
