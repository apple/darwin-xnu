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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * IOPacketQueue.h
 *
 * HISTORY
 * 9-Dec-1998       Joe Liu (jliu) created.
 *
 */

#ifndef _IOPACKETQUEUE_H
#define _IOPACKETQUEUE_H

#include <libkern/c++/OSObject.h>
#include <IOKit/IOLocks.h>

// Forward declarations.
//
struct mbuf;
struct IOMbufQueue;

// We do not want the enqueue/dequeue macros defined in queue.h.
//
// #warning queue.h should not be included
#undef enqueue(queue,elt)
#undef dequeue(queue)

/*! @class IOPacketQueue : public OSObject
    @abstract Implements a bounded FIFO queue of mbuf packets. Packets are
    removed from the head of the queue (dequeue), and new packets are added
    to the tail of the queue (enqueue). A spinlock is used to synchronize
    access to the queue between methods that have a "lock" prefix. */

class IOPacketQueue : public OSObject
{   
    OSDeclareDefaultStructors( IOPacketQueue )

protected:
    IOMbufQueue *   _queue;   // mbuf queue
    IOSimpleLock *  _lock;    // spinlock for synchronized methods

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *_reserved;

/*! @function free
    @abstract Free the IOPacketQueue object.
    @discussion All packets held by the queue are released back to the free
    pool, resource are deallocated, then super::free() is called. */

    virtual void free();

/*! @var IOPacketQueueDefaultCapacity Describes the default capacity of the 
    queue object. The capacity is only observed by the enqueue() method.
    Therefore, it is possible for the size of the queue to exceed its
    capacity when other methods, such as prepend(), are used to add packets
    to the queue. */

    static const UInt32 IOPacketQueueDefaultCapacity = 100;

public:

/*! @function withCapacity
    @abstract Factory method that will construct and initialize an
    IOPacketQueue object.
    @param capacity The initial capacity of the queue object. Can be
    later changed by calling the setCapacity() method.
    @result An IOPacketQueue instance on success, or 0 otherwise. */

    static IOPacketQueue * withCapacity(UInt32 capacity = 
                                        IOPacketQueueDefaultCapacity);

/*! @function initWithCapacity
    @abstract Initialize an IOPacketQueue object.
    @discussion Initialize an IOPacketQueue object with the given capacity.
    @param capacity The initial capacity of the queue. Can be later changed
    by calling the setCapacity() method.
    @result true if initialized successfully, false otherwise. */

    virtual bool initWithCapacity(UInt32 capacity = 
                                  IOPacketQueueDefaultCapacity);

/*! @function getSize
    @abstract Get the size of the queue.
    @result The number of packets currently held by the queue. */

    virtual UInt32 getSize() const;

/*! @function setCapacity
    @abstract Change the capacity of the queue.
    @param capacity The new capacity.
    @result true if the new capacity was accepted, false otherwise. */

    virtual bool setCapacity(UInt32 capacity);

/*! @function getCapacity
    @abstract Get the current capacity of the queue.
    @result The current queue capacity. */

    virtual UInt32 getCapacity() const;

/*! @function peek
    @abstract Examine the packet at the head of the queue without
    removing it from the queue.
    @discussion A following call to peek() or dequeue() will return
    the same packet. The caller must never modify the mbuf packet returned.
    @result The packet at the head of the queue. */

    virtual const struct mbuf * peek() const;

/*! @function prepend
    @abstract Add a chain of packets to the head of the queue.
    @param m A chain of packets to add to the head of the queue. */

    virtual void prepend(struct mbuf * m);

/*! @function prepend
    @abstract Remove all packets from the specified queue, and add them
    to the head of this queue.
    @param queue The source IOPacketQueue object containing the packets to
    be transferred. */

    virtual void prepend(IOPacketQueue * queue);

/*! @function lockPrepend
    @abstract Add a chain of packets to the head of a synchronized queue.
    @discussion A spinlock is used to synchronize access to the queue.
    @param m A chain of packets to add to the head of the queue.
    @result Will always return true. */

    virtual void lockPrepend(struct mbuf * m);

/*! @function enqueue
    @abstract Add a chain of packets to the tail of the queue.
    @discussion Packets are not added if the size of the queue has reached
    its capacity.
    @param m A chain of packets to add to the tail of the queue.
    @result true on success, or false to indicate over-capacity and refusal
    to accept the packet chain provided. */

    virtual bool enqueue(struct mbuf * m);

/*! @function enqueue
    @abstract Remove all packets from the specified queue, and add them
    to the tail of this queue.
    @param queue The source IOPacketQueue object containing the packets to
    be transferred.
    @result Always return true. */

    virtual bool enqueue(IOPacketQueue * queue);

/*! @function enqueueWithDrop
    @abstract Add a chain of packets to the tail of the queue. Packets are
    dropped if the size of the queue has reached its capacity.
    @param m A chain of packets to add to the tail of the queue.
    @result The number of packets dropped and freed by the queue. */

    virtual UInt32 enqueueWithDrop(struct mbuf * m);

/*! @function lockEnqueue
    @abstract Add a chain of packets to the tail of a synchronized queue.
    @discussion Packets are not added if the size of the queue has reached
    its capacity. A spinlock is used to synchronize access to the queue.
    @param m A chain of packets to add to the tail of the queue.
    @result true on success, or false to indicate over-capacity and refusal
    to accept the packet chain provided. */

    virtual bool lockEnqueue(struct mbuf * m);

/*! @function lockEnqueueWithDrop
    @abstract Add a chain of packets to the tail of a synchronized queue.
    Packets are dropped if the size of the queue has reached its capacity.
    @discussion A spinlock is used to synchronize access to the queue.
    @param m A chain of packets to add to the tail of the queue.
    @result The number of packets dropped and freed by the queue. */

    virtual UInt32 lockEnqueueWithDrop(struct mbuf * m);

/*! @function dequeue
    @abstract Remove a single packet from the head of the queue.
    @result A packet removed from the head of the queue, or NULL if the
    queue was empty. */

    virtual struct mbuf * dequeue();

/*! @function lockDequeue
    @abstract Remove a single packet from the head of a synchronized queue.
    @discussion A spinlock is used to synchronize access to the queue.
    @result A packet removed from the head of the queue, or NULL if the
    queue was empty. */

    virtual struct mbuf * lockDequeue();

/*! @function dequeueAll
    @abstract Remove all packets from the queue and return the head of the
    packet chain.
    @discussion The size of the queue is cleared to zero.
    @result The head of a packet chain linking all packets that were held
    in the queue, or NULL if the queue was empty. */

    virtual struct mbuf * dequeueAll();

/*! @function lockDequeueAll
    @abstract Remove all packets from a synchronized queue and return the
    head of the packet chain.
    @discussion The size of the queue is cleared to zero. A spinlock is used
    to synchronize access to the queue.
    @result The head of a packet chain linking all packets that were held
    in the queue, or NULL if the queue was empty. */

    virtual struct mbuf * lockDequeueAll();

/*! @function flush
    @abstract Free all packets currently held in the queue and release them
    back to the free mbuf pool.
    @discussion The size of the queue is cleared to zero.
    @result The number of packets freed. */

    virtual UInt32 flush();

/*! @function lockFlush
    @abstract Free all packets currently held in a synchronized queue and
    release them back to the free mbuf pool.
    @discussion The size of the queue is cleared to zero. A spinlock is used
    to synchronize access to the queue.
    @result The number of packets freed. */

    virtual UInt32 lockFlush();

    // Virtual Pad functions
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  0);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  1);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  2);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  3);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  4);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  5);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  6);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  7);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  8);
    OSMetaClassDeclareReservedUnused( IOPacketQueue,  9);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 10);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 11);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 12);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 13);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 14);
    OSMetaClassDeclareReservedUnused( IOPacketQueue, 15);
};

#endif /* !_IOPACKETQUEUE_H */
