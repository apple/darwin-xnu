/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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

#define DISABLE_DATAQUEUE_WARNING

#include <IOKit/IODataQueue.h>

#undef DISABLE_DATAQUEUE_WARNING

#include <IOKit/IODataQueueShared.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/OSAtomic.h>

struct IODataQueueInternal
{
    mach_msg_header_t msg;
    UInt32            queueSize;
};

#ifdef enqueue
#undef enqueue
#endif

#ifdef dequeue
#undef dequeue
#endif

#define super OSObject

OSDefineMetaClassAndStructors(IODataQueue, OSObject)

IODataQueue *IODataQueue::withCapacity(UInt32 size)
{
    IODataQueue *dataQueue = new IODataQueue;

    if (dataQueue) {
        if  (!dataQueue->initWithCapacity(size)) {
            dataQueue->release();
            dataQueue = 0;
        }
    }

    return dataQueue;
}

IODataQueue *IODataQueue::withEntries(UInt32 numEntries, UInt32 entrySize)
{
    IODataQueue *dataQueue = new IODataQueue;

    if (dataQueue) {
        if (!dataQueue->initWithEntries(numEntries, entrySize)) {
            dataQueue->release();
            dataQueue = 0;
        }
    }

    return dataQueue;
}

Boolean IODataQueue::initWithCapacity(UInt32 size)
{
    vm_size_t allocSize = 0;

    if (!super::init()) {
        return false;
    }

    if (size > UINT32_MAX - DATA_QUEUE_MEMORY_HEADER_SIZE) {
        return false;
    }
    
    allocSize = round_page(size + DATA_QUEUE_MEMORY_HEADER_SIZE);

    if (allocSize < size) {
        return false;
    }

    assert(!notifyMsg);
    notifyMsg = IONew(IODataQueueInternal, 1);
	if (!notifyMsg) {
		return false;
	}
    bzero(notifyMsg, sizeof(IODataQueueInternal));
    ((IODataQueueInternal *)notifyMsg)->queueSize = size;

    dataQueue = (IODataQueueMemory *)IOMallocAligned(allocSize, PAGE_SIZE);
    if (dataQueue == 0) {
        return false;
    }
    bzero(dataQueue, allocSize);

    dataQueue->queueSize    = size;
//  dataQueue->head         = 0;
//  dataQueue->tail         = 0;

    return true;
}

Boolean IODataQueue::initWithEntries(UInt32 numEntries, UInt32 entrySize)
{
    // Checking overflow for (numEntries + 1)*(entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE):
    //  check (entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE)
    if ((entrySize > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) ||
        //  check (numEntries + 1)
        (numEntries > UINT32_MAX-1) ||
        //  check (numEntries + 1)*(entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE)
        (entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE > UINT32_MAX/(numEntries+1))) {
        return false;
    }
    
    return (initWithCapacity((numEntries + 1) * (DATA_QUEUE_ENTRY_HEADER_SIZE + entrySize)));
}

void IODataQueue::free()
{
	if (notifyMsg) {
		if (dataQueue) {
			IOFreeAligned(dataQueue, round_page(((IODataQueueInternal *)notifyMsg)->queueSize + DATA_QUEUE_MEMORY_HEADER_SIZE));
			dataQueue = NULL;
		}

		IODelete(notifyMsg, IODataQueueInternal, 1);
		notifyMsg = NULL;
    }

    super::free();

    return;
}

Boolean IODataQueue::enqueue(void * data, UInt32 dataSize)
{
    UInt32             head;
    UInt32             tail;
    UInt32             newTail;
    const UInt32       entrySize = dataSize + DATA_QUEUE_ENTRY_HEADER_SIZE;
    UInt32             queueSize;
    IODataQueueEntry * entry;

    // Check for overflow of entrySize
    if (dataSize > UINT32_MAX - DATA_QUEUE_ENTRY_HEADER_SIZE) {
        return false;
    }

    // Force a single read of head and tail
    // See rdar://problem/40780584 for an explanation of relaxed/acquire barriers
    tail = __c11_atomic_load((_Atomic UInt32 *)&dataQueue->tail, __ATOMIC_RELAXED);
    head = __c11_atomic_load((_Atomic UInt32 *)&dataQueue->head, __ATOMIC_ACQUIRE);

    // Check for underflow of (dataQueue->queueSize - tail)
    queueSize = ((IODataQueueInternal *) notifyMsg)->queueSize;
    if ((queueSize < tail) || (queueSize < head)) {
        return false;
    }

    if ( tail >= head )
    {
        // Is there enough room at the end for the entry?
        if ((entrySize <= UINT32_MAX - tail) &&
            ((tail + entrySize) <= queueSize) )
        {
            entry = (IODataQueueEntry *)((UInt8 *)dataQueue->queue + tail);

            entry->size = dataSize;
            memcpy(&entry->data, data, dataSize);

            // The tail can be out of bound when the size of the new entry
            // exactly matches the available space at the end of the queue.
            // The tail can range from 0 to dataQueue->queueSize inclusive.

            newTail = tail + entrySize;
        }
        else if ( head > entrySize )     // Is there enough room at the beginning?
        {
            // Wrap around to the beginning, but do not allow the tail to catch
            // up to the head.

            dataQueue->queue->size = dataSize;

            // We need to make sure that there is enough room to set the size before
            // doing this. The user client checks for this and will look for the size
            // at the beginning if there isn't room for it at the end.

            if ( ( queueSize - tail ) >= DATA_QUEUE_ENTRY_HEADER_SIZE )
            {
                ((IODataQueueEntry *)((UInt8 *)dataQueue->queue + tail))->size = dataSize;
            }

            memcpy(&dataQueue->queue->data, data, dataSize);
            newTail = entrySize;
        }
        else
        {
            return false;    // queue is full
        }
    }
    else
    {
        // Do not allow the tail to catch up to the head when the queue is full.
        // That's why the comparison uses a '>' rather than '>='.

        if ( (head - tail) > entrySize )
        {
            entry = (IODataQueueEntry *)((UInt8 *)dataQueue->queue + tail);

            entry->size = dataSize;
            memcpy(&entry->data, data, dataSize);
            newTail = tail + entrySize;
        }
        else
        {
            return false;    // queue is full
        }
    }

	// Publish the data we just enqueued
	__c11_atomic_store((_Atomic UInt32 *)&dataQueue->tail, newTail, __ATOMIC_RELEASE);

	if (tail != head) {
		//
		// The memory barrier below paris with the one in ::dequeue
		// so that either our store to the tail cannot be missed by
		// the next dequeue attempt, or we will observe the dequeuer
		// making the queue empty.
		//
		// Of course, if we already think the queue is empty,
		// there's no point paying this extra cost.
		//
		__c11_atomic_thread_fence(__ATOMIC_SEQ_CST);
		head = __c11_atomic_load((_Atomic UInt32 *)&dataQueue->head, __ATOMIC_RELAXED);
	}

	if (tail == head) {
		// Send notification (via mach message) that data is now available.
		sendDataAvailableNotification();
	}
	return true;
}

void IODataQueue::setNotificationPort(mach_port_t port)
{
    mach_msg_header_t * msgh;

    msgh = &((IODataQueueInternal *) notifyMsg)->msg;
	bzero(msgh, sizeof(mach_msg_header_t));
	msgh->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
	msgh->msgh_size = sizeof(mach_msg_header_t);
	msgh->msgh_remote_port = port;
}

void IODataQueue::sendDataAvailableNotification()
{
    kern_return_t       kr;
    mach_msg_header_t * msgh;

    msgh = &((IODataQueueInternal *) notifyMsg)->msg;
    if (msgh->msgh_remote_port) {
        kr = mach_msg_send_from_kernel_with_options(msgh, msgh->msgh_size, MACH_SEND_TIMEOUT, MACH_MSG_TIMEOUT_NONE);
        switch(kr) {
            case MACH_SEND_TIMED_OUT:    // Notification already sent
            case MACH_MSG_SUCCESS:
            case MACH_SEND_NO_BUFFER:
                break;
            default:
                IOLog("%s: dataAvailableNotification failed - msg_send returned: %d\n", /*getName()*/"IODataQueue", kr);
                break;
        }
    }
}

IOMemoryDescriptor *IODataQueue::getMemoryDescriptor()
{
    IOMemoryDescriptor *descriptor = 0;
    UInt32              queueSize;

    queueSize = ((IODataQueueInternal *) notifyMsg)->queueSize;
    if (dataQueue != 0) {
        descriptor = IOMemoryDescriptor::withAddress(dataQueue, queueSize + DATA_QUEUE_MEMORY_HEADER_SIZE, kIODirectionOutIn);
    }

    return descriptor;
}


