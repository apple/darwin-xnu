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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IOBasicOutputQueue.h
 * 
 * HISTORY
 *
 */

#ifndef _IOBASICOUTPUTQUEUE_H
#define _IOBASICOUTPUTQUEUE_H

#include <IOKit/IOLocks.h>
#include <IOKit/network/IOOutputQueue.h>
#include <IOKit/network/IOPacketQueue.h>  // FIXME - remove

struct IOMbufQueue;

/*! @class IOBasicOutputQueue : public IOOutputQueue
    @abstract A concrete implementation of an IOOutputQueue. This object
    uses a spinlock to protect the packet queue from multiple producers.
    A single producer is promoted to become a consumer when the queue is
    not active. Otherwise, the producer will simply queue the packet and
    return without blocking.

    The flow of packets from the queue to its target can be controlled
    by calling methods such as start(), stop(), or service(). The target
    is expected to call those methods from a single threaded context,
    i.e. the work loop context in a network driver. In addition, the
    target must also return a status for every packet delivered by the
    consumer thread. This return value is the only mechanism that the
    target can use to manage the queue when it is running on the
    consumer thread. */

class IOBasicOutputQueue : public IOOutputQueue
{
    OSDeclareDefaultStructors( IOBasicOutputQueue )

private:
	static IOReturn dispatchNetworkDataNotification(void *          target,
                                                    void *          param,
                                                    IONetworkData * data,
                                                    UInt32          type);

    void dequeue();
    
protected:
    OSObject *            _target;
    IOOutputAction        _action;
    IOOutputQueueStats *  _stats;
    IONetworkData *       _statsData;
	IOSimpleLock *        _spinlock;
    IOMbufQueue *         _inQueue;
    IOMbufQueue *         _queues[2];
    volatile bool         _waitDequeueDone;
    volatile UInt32       _state;
    volatile UInt32       _serviceCount;

/*! @function serviceThread
    @abstract Method called by the scheduled service thread when it
    starts to run.
    @discussion Provide an implementation for the serviceThread() method
    defined in IOOutputQueue. The service thread is scheduled by service()
    to restart a stalled queue when the kServiceAsync options is given.
    @param A parameter that was given to scheduleServiceThread().
    This parameter is not used. */

    virtual void serviceThread(void * param);

/*! @function output
    @abstract Transfer all packets in the mbuf queue to the target.
    @param queue A queue of output packets.
    @param state Return a state bit defined by IOBasicOutputQueue that
    declares the new state of the queue following this method call.
    A kStateStalled is returned if the queue should stall, otherwise 0
    is returned. */

    virtual void output(IOMbufQueue * queue, UInt32 * state);

/*! @function free
    @abstract Free the IOBasicOutputQueue object.
    @discussion Release allocated resources, then call super::free(). */

    virtual void free();

/*! @function handleNetworkDataAccess
    @abstract Handle an external access to the IONetworkData object
    returned by getStatisticsData().
    @param data The IONetworkData object being accessed.
    @param type Describes the type of access being performed.
    @param param An optional parameter for the handler.
    @result kIOReturnSuccess on success, or an error code otherwise. */

    virtual IOReturn handleNetworkDataAccess(IONetworkData * data,
                                             UInt32          type,
                                             void *          param);

public:

/*! @function init
    @abstract Initialize an IOBasicOutputQueue object.
    @param target The object that will handle packets removed from the
    queue, and is usually a subclass of IONetworkController.
    @param action The function that will handle packets removed from the
    queue.
    @param capacity The initial capacity of the output queue.
    @result true if initialized successfully, false otherwise. */

    virtual bool init(OSObject *     target,
                      IOOutputAction action,
                      UInt32         capacity = 0);

/*! @function withTarget
    @abstract Factory method that will construct and initialize an
    IOBasicOutputQueue object.
    @param target An IONetworkController object that will handle packets
    removed from the queue.
    @param capacity The initial capacity of the output queue.
    @result An IOBasicOutputQueue object on success, or 0 otherwise. */

    static IOBasicOutputQueue * withTarget(IONetworkController * target,
                                           UInt32                capacity = 0);

/*! @function withTarget
    @abstract Factory method that will construct and initialize an
    IOBasicOutputQueue object.
    @param target The object that will handle packets removed from the
    queue.
    @param action The function that will handle packets removed from the
    queue.
    @param capacity The initial capacity of the output queue.
    @result An IOBasicOutputQueue object on success, or 0 otherwise. */

    static IOBasicOutputQueue * withTarget(OSObject *     target,
                                           IOOutputAction action,
                                           UInt32         capacity = 0);

/*! @function enqueue
    @abstract Called by a client to add a packet, or a chain of packets,
    to the queue.
    @discussion A packet is described by a mbuf chain, while a chain
    of packets is constructed by linking multiple mbuf chains via the
    m_nextpkt field. This method can be called by multiple client
    threads.
    @param m A single packet, or a chain of packets.
    @param param A parameter provided by the caller.
    @result Always return 0. */

    virtual UInt32 enqueue(struct mbuf * m, void * param);

/*! @function start
    @abstract Start up the packet flow between the queue and its target.
    @discussion Called by the target to start the queue. This will allow
    packets to be removed from the queue, and then delivered to the target.
    @result true if the queue was started successfully, false otherwise. */

    virtual bool start();

/*! @function stop
    @abstract Stop the packet flow between the queue and its target.
    @discussion Stop the queue and prevent it from sending packets to its
    target. This call is synchronous and it may block. After this method
    returns, the queue will no longer call the registered target/action,
    even as new packets are added to the queue. The queue will continue to
    absorb new packets until the size of the queue reaches its capacity.
    The registered action must never call stop(), or a deadlock will occur.
    @result Returns the previous running state of the queue,
    true if the queue was running, false if the queue was already stopped. */

    virtual bool stop();

/*! @enum An enumeration of the option bits recognized by service().
    @constant kServiceAsync Set this option to service the queue in
    an asynchronous manner. The service() call will not block, but a
    scheduling latency will be introduced before the queue is serviced. */

    enum {
        kServiceAsync = 0x1
    };

/*! @function service
    @abstract Service a queue that was stalled by the target.
    @discussion A target that stalls the queue must call service() when
    it becomes ready to accept more packets. Calling this methods when the
    queue is not stalled is harmless.
    @result true if the queue was stalled and there were packets sitting in
    the queue awaiting delivery, false otherwise. */

    virtual bool service(IOOptionBits options = 0);

/*! @function flush
    @abstract Drop and free all packets currently held by the queue.
    @discussion To ensure that all packets are removed from the queue,
    stop() should be called prior to flush(), to make sure there are
    no packets in-flight and being delivered to the target.
    @result The number of packets that were dropped and freed. */

    virtual UInt32 flush();

/*! @function setCapacity
    @abstract Change the number of packets that the queue can hold
    before it begins to drop excess packets.
    @param capacity The new desired capacity.
    @result true if the new capacity was accepted, false otherwise. */

    virtual bool setCapacity(UInt32 capacity);

/*! @function getCapacity
    @abstract Get the number of packets that the queue can hold.
    @discussion The queue will begin to drop incoming packets when the
    size of queue reaches its capacity.
    @result The current queue capacity. */

    virtual UInt32 getCapacity() const;

/*! @function getSize
    @abstract Get the number of packets currently held in the queue.
    @result The size of the queue. */

    virtual UInt32 getSize() const;

/*! @function getDropCount
    @abstract Get the number of packets dropped by the queue.
    @result The number of packets dropped due to over-capacity, or by
    external calls to the flush() method. */

    virtual UInt32 getDropCount();

/*! @function getOutputCount
    @sbstract Get the number of packets accepted by the target.
    @result The number of times that kIOOutputStatusAccepted is returned by
    the target. */

    virtual UInt32 getOutputCount();

/*! @function getRetryCount
    @abstract Get the number of instances when the target has refused to
    accept the packet provided.
    @result The number of times that kIOOutputStatusRetry is returned by the
    target. */

    virtual UInt32 getRetryCount();

/*! @function getStallCount
    @abstract Get the number of instances when the target has stalled the
    queue.
    @result The number of times that kIOOutputCommandStall is returned by the
    target. */

    virtual UInt32 getStallCount();

/*! @enum An enumeration of the bits in the value returned by getState().
    @constant kStateRunning Set when the queue is running. Calling start()
    and stop() will set or clear this bit.
    @constant kStateStalled Set when the queue is stalled by the target.
    @constant kStateActive  Set when a consumer thread is actively removing
    packets from the queue and passing them to the target. */

    enum {
        kStateRunning            = 0x1,
        kStateOutputStalled      = 0x2,
        kStateOutputActive       = 0x4,
        kStateOutputServiceMask  = 0xff00
    };

/*! @function getState
    @abstract Get the state of the queue object.
    @result The current state of the queue object. */ 

    virtual UInt32 getState() const;

/*! @function getStatisticsData
    @abstract Return an IONetworkData object containing statistics counters
    updated by the queue.
    @result An IONetworkData object. */

	virtual IONetworkData * getStatisticsData() const;
};

#endif /* !_IOBASICOUTPUTQUEUE_H */
