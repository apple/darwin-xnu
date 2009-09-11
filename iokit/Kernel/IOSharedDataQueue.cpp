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

#include <IOKit/IOSharedDataQueue.h>
#include <IOKit/IODataQueueShared.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>

#ifdef dequeue
#undef dequeue
#endif

#define super IODataQueue

OSDefineMetaClassAndStructors(IOSharedDataQueue, IODataQueue)

IOSharedDataQueue *IOSharedDataQueue::withCapacity(UInt32 size)
{
    IOSharedDataQueue *dataQueue = new IOSharedDataQueue;

    if (dataQueue) {
        if  (!dataQueue->initWithCapacity(size)) {
            dataQueue->release();
            dataQueue = 0;
        }
    }

    return dataQueue;
}

IOSharedDataQueue *IOSharedDataQueue::withEntries(UInt32 numEntries, UInt32 entrySize)
{
    IOSharedDataQueue *dataQueue = new IOSharedDataQueue;

    if (dataQueue) {
        if (!dataQueue->initWithEntries(numEntries, entrySize)) {
            dataQueue->release();
            dataQueue = 0;
        }
    }

    return dataQueue;
}

Boolean IOSharedDataQueue::initWithCapacity(UInt32 size)
{
    IODataQueueAppendix *   appendix;
    
    if (!super::init()) {
        return false;
    }
    
    dataQueue = (IODataQueueMemory *)IOMallocAligned(round_page(size + DATA_QUEUE_MEMORY_HEADER_SIZE + DATA_QUEUE_MEMORY_APPENDIX_SIZE), PAGE_SIZE);
    if (dataQueue == 0) {
        return false;
    }

    dataQueue->queueSize    = size;
    dataQueue->head         = 0;
    dataQueue->tail         = 0;
    
    appendix            = (IODataQueueAppendix *)((UInt8 *)dataQueue + size + DATA_QUEUE_MEMORY_HEADER_SIZE);
    appendix->version   = 0;
    notifyMsg           = &(appendix->msgh);
    setNotificationPort(MACH_PORT_NULL);

    return true;
}

void IOSharedDataQueue::free()
{
    if (dataQueue) {
        IOFreeAligned(dataQueue, round_page(dataQueue->queueSize + DATA_QUEUE_MEMORY_HEADER_SIZE + DATA_QUEUE_MEMORY_APPENDIX_SIZE));
        dataQueue = NULL;
    }

    super::free();
}

IOMemoryDescriptor *IOSharedDataQueue::getMemoryDescriptor()
{
    IOMemoryDescriptor *descriptor = 0;

    if (dataQueue != 0) {
        descriptor = IOMemoryDescriptor::withAddress(dataQueue, dataQueue->queueSize + DATA_QUEUE_MEMORY_HEADER_SIZE + DATA_QUEUE_MEMORY_APPENDIX_SIZE, kIODirectionOutIn);
    }

    return descriptor;
}


IODataQueueEntry * IOSharedDataQueue::peek()
{
    IODataQueueEntry *entry = 0;

    if (dataQueue && (dataQueue->head != dataQueue->tail)) {
        IODataQueueEntry *  head		= 0;
        UInt32              headSize    = 0;
        UInt32              headOffset  = dataQueue->head;
        UInt32              queueSize   = dataQueue->queueSize;

        head 		= (IODataQueueEntry *)((char *)dataQueue->queue + headOffset);
        headSize 	= head->size;
        
		// Check if there's enough room before the end of the queue for a header.
        // If there is room, check if there's enough room to hold the header and
        // the data.

        if ((headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize) ||
            ((headOffset + headSize + DATA_QUEUE_ENTRY_HEADER_SIZE) > queueSize))
        {
            // No room for the header or the data, wrap to the beginning of the queue.
            entry = dataQueue->queue;
        } else {
            entry = head;
        }
    }

    return entry;
}

Boolean IOSharedDataQueue::dequeue(void *data, UInt32 *dataSize)
{
    Boolean             retVal          = TRUE;
    IODataQueueEntry *  entry           = 0;
    UInt32              entrySize       = 0;
    UInt32              newHeadOffset   = 0;

    if (dataQueue) {
        if (dataQueue->head != dataQueue->tail) {
            IODataQueueEntry *  head		= 0;
            UInt32              headSize    = 0;
            UInt32              headOffset  = dataQueue->head;
            UInt32              queueSize   = dataQueue->queueSize;

            head 		= (IODataQueueEntry *)((char *)dataQueue->queue + headOffset);
            headSize 	= head->size;
            
            // we wraped around to beginning, so read from there
			// either there was not even room for the header
			if ((headOffset + DATA_QUEUE_ENTRY_HEADER_SIZE > queueSize) ||
				// or there was room for the header, but not for the data
				((headOffset + headSize + DATA_QUEUE_ENTRY_HEADER_SIZE) > queueSize)) {
                entry           = dataQueue->queue;
                entrySize       = entry->size;
                newHeadOffset   = entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE;
            // else it is at the end
            } else {
                entry           = head;
                entrySize       = entry->size;
                newHeadOffset   = headOffset + entrySize + DATA_QUEUE_ENTRY_HEADER_SIZE;
            }
        }

        if (entry) {
            if (data) {
                if (dataSize) {
                    if (entrySize <= *dataSize) {
                        memcpy(data, &(entry->data), entrySize);
                        dataQueue->head = newHeadOffset;
                    } else {
                        retVal = FALSE;
                    }
                } else {
                    retVal = FALSE;
                }
            } else {
                dataQueue->head = newHeadOffset;
            }

            if (dataSize) {
                *dataSize = entrySize;
            }
        } else {
            retVal = FALSE;
        }
    } else {
        retVal = FALSE;
    }
    
    return retVal;
}


OSMetaClassDefineReservedUnused(IOSharedDataQueue, 0);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 1);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 2);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 3);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 4);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 5);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 6);
OSMetaClassDefineReservedUnused(IOSharedDataQueue, 7);
