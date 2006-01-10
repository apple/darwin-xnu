/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
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
]*/
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimeStamp.h>

#include <mach/sync_policy.h>

#define NUM_FIELDS_IN_COMMAND	4
typedef struct commandEntryTag {
    void *f[NUM_FIELDS_IN_COMMAND];
} commandEntryT;

#define super IOEventSource

OSDefineMetaClassAndStructors(IOCommandQueue, IOEventSource)

/*[
Instance Methods

initWithNext:owner:action:size:
    - initWithNext: (IOEventSource *) inNext
            owner: (id) inOwner
            action: (SEL) inAction
              size: (int) inSize;

Primary initialiser for the IOCommandQueue class.  Returns an
IOCommandQueue object that is initialised with the next object in
the chain and the owner and action. On return the signalWorkAvailableIMP
has been cached for this function.

If the object fails to initialise for some reason then [self free] will
be called and nil will be returned.

See also: initWithNext:owner:action:(IOEventSource)
]*/
bool IOCommandQueue::init(OSObject *inOwner,
                          IOCommandQueueAction inAction,
                          int inSize)
{
    if ( !super::init(inOwner, (IOEventSourceAction) inAction) )
        return false;
    
    if (KERN_SUCCESS
    !=  semaphore_create(kernel_task, &producerSema, SYNC_POLICY_FIFO, inSize))
        return false;

    size = inSize + 1; /* Allocate one more entry than needed */

    queue = (void *)kalloc(size * sizeof(commandEntryT));
    if (!queue)
        return false;

    producerLock = IOLockAlloc();
    if (!producerLock)
        return false;

    producerIndex = consumerIndex = 0;

    return true;
}

IOCommandQueue *
IOCommandQueue::commandQueue(OSObject *inOwner,
                             IOCommandQueueAction inAction,
                             int inSize)
{
    IOCommandQueue *me = new IOCommandQueue;

    if (me && !me->init(inOwner, inAction, inSize)) {
        me->free();
        return 0;
    }

    return me;
}

/*[
free
    - free

Mandatory free of the object independent of the current retain count.
Returns nil.
]*/
void IOCommandQueue::free()
{
    if (queue)
        kfree(queue, size * sizeof(commandEntryT));
    if (producerSema)
        semaphore_destroy(kernel_task, producerSema);
    if (producerLock)
        IOLockFree(producerLock);

    super::free();
}

#if NUM_FIELDS_IN_COMMAND != 4
#error IOCommandQueue::checkForWork needs to be updated for new command size
#endif

bool IOCommandQueue::checkForWork()
{
    void *field0, *field1, *field2, *field3;

    if (!enabled || consumerIndex == producerIndex)
        return false;

    {
        commandEntryT *q = (commandEntryT *) queue;
        int localIndex = consumerIndex;

        field0 = q[localIndex].f[0]; field1 = q[localIndex].f[1];
        field2 = q[localIndex].f[2]; field3 = q[localIndex].f[3];
        semaphore_signal(producerSema);
    }

    if (++consumerIndex >= size)
        consumerIndex = 0;

    IOTimeStampConstant(IODBG_CMDQ(IOCMDQ_ACTION),
			(unsigned int) action, (unsigned int) owner);

    (*(IOCommandQueueAction) action)(owner, field0, field1, field2, field3);

    return (consumerIndex != producerIndex);
}

/*[
enqueueSleep:command:
    - (kern_return_t) enqueueSleepRaw: (BOOL) gotoSleep
                               field0: (void *) field0 field1: (void *) field1
                               field2: (void *) field2 field3: (void *) field3;

Key method that enqueues the four input fields onto the command queue
and calls signalWorkAvailable to indicate that work is available to the
consumer.  This routine is safe against multiple threaded producers.

A family of convenience functions have been provided to assist with the
enqueueing of an method selector and an integer tag.  This relies on the
IODevice rawCommandOccurred... command to forward on the requests.

See also: signalWorkAvailable, checkForWork
]*/
#if NUM_FIELDS_IN_COMMAND != 4
#error IOCommandQueue::enqueueCommand needs to be updated
#endif

kern_return_t
IOCommandQueue::enqueueCommand(bool gotoSleep,
                               void *field0, void *field1,
                               void *field2, void *field3)
{
    kern_return_t rtn = KERN_SUCCESS;
    int retry;

    /* Make sure there is room in the queue before doing anything else */

    if (gotoSleep) {
        retry = 0;
        do
        rtn = semaphore_wait(producerSema);
        while(     (KERN_SUCCESS != rtn)
		&& (KERN_OPERATION_TIMED_OUT != rtn)
		&& (KERN_SEMAPHORE_DESTROYED != rtn)
		&& (KERN_TERMINATED != rtn)
		&& ((retry++) < 4));
    } else
        rtn = semaphore_timedwait(producerSema, MACH_TIMESPEC_ZERO);

    if (KERN_SUCCESS != rtn)
        return rtn;

    /* Block other producers */
    IOTakeLock(producerLock);

    /*
     * Make sure that we update the current producer entry before we
     * increment the producer pointer.  This avoids a nasty race as the
     * as the test for work is producerIndex != consumerIndex and a signal.
     */
    {
        commandEntryT *q = (commandEntryT *) queue;
        int localIndex = producerIndex;

        q[localIndex].f[0] = field0; q[localIndex].f[1] = field1;
        q[localIndex].f[2] = field2; q[localIndex].f[3] = field3;
    }
    if (++producerIndex >= size)
        producerIndex = 0;

    /* Clear to allow other producers to go now */
    IOUnlock(producerLock);

    /*
     * Right we have created some new work, we had better make sure that
     * we notify the work loop that it has to test producerIndex.
     */
    signalWorkAvailable();
    return rtn;
}

int IOCommandQueue::performAndFlush(OSObject *target,
                                    IOCommandQueueAction inAction)
{
    int numEntries;
    kern_return_t rtn;

    // Set the defaults if necessary
    if (!target)
        target = owner;
    if (!inAction)
        inAction = (IOCommandQueueAction) action;

    // Lock out the producers first
    do {
        rtn = semaphore_timedwait(producerSema, MACH_TIMESPEC_ZERO);
    } while (rtn == KERN_SUCCESS);

    // now step over all remaining entries in the command queue
    for (numEntries = 0; consumerIndex != producerIndex; ) {
        void *field0, *field1, *field2, *field3;

        {
            commandEntryT *q = (commandEntryT *) queue;
            int localIndex = consumerIndex;

            field0 = q[localIndex].f[0]; field1 = q[localIndex].f[1];
            field2 = q[localIndex].f[2]; field3 = q[localIndex].f[3];
        }

        if (++consumerIndex >= size)
            consumerIndex = 0;

        (*inAction)(target, field0, field1, field2, field3);
    }

    // finally refill the producer semaphore to size - 1
    for (int i = 1; i < size; i++)
        semaphore_signal(producerSema);

    return numEntries;
}
