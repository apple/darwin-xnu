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
 * IOOutputQueue.h
 *
 * HISTORY
 * 2-Feb-1999       Joe Liu (jliu) created.
 *
 */

#ifndef _IOOUTPUTQUEUE_H
#define _IOOUTPUTQUEUE_H

#include <IOKit/network/IONetworkInterface.h>

// Forward declarations.
//
struct mbuf;
class  IONetworkData;

// FIXME - We do not want the enqueue/dequeue macros defined in queue.h.
//
#undef enqueue(queue,elt)
#undef dequeue(queue)

// FIXME - Belongs in IOBasicOutputQueue.h
//
/*! @enum The status of the packet sent to the target.
    @constant kIOOutputStatusMask Define the status field in the return code.
    @constant kIOOutputStatusAccept Packet was accepted by the target.
    @constant kIOOutputStatusDropped Packet accepted, but was also dropped.
    @constant kIOOutputStatusRetry Target ran out of resources, and is unable
    to accept the packet. The ownership of the packet reverts back to the
    queue. */

enum {
    kIOOutputStatusMask     = 0x00ff,
    kIOOutputStatusAccepted = 0x0000,
    kIOOutputStatusDropped  = 0x0001,
    kIOOutputStatusRetry    = 0x0002
};

/*! @enum A command requested by the target.
    @constant kIOOutputCommandMask Define the command field in the return code.
    @constant kIOOutputCommandNone No command.
    @constant kIOOutputCommandStall A command to stall the queue. */

enum {
    kIOOutputCommandMask    = 0xff00,
    kIOOutputCommandNone    = 0x0000,
    kIOOutputCommandStall   = 0x0100
};

/*! @enum Definition of common return codes returned by the target's
          output handler.
    @constant kIOReturnOutputSuccess Packet was accepted.
    @constant kIOReturnOutputDropped Packet was dropped.
    @constant kIOReturnOutputStall   Stall the queue and retry the same packet
              when the queue is restarted. */

enum {
    kIOReturnOutputSuccess = (kIOOutputStatusAccepted | kIOOutputCommandNone),
    kIOReturnOutputDropped = (kIOOutputStatusDropped  | kIOOutputCommandNone),
    kIOReturnOutputStall   = (kIOOutputStatusRetry    | kIOOutputCommandStall)
};

/*! @class IOOutputQueue : public OSObject
    @abstract A packet queue that supports multiple producers, and a single
    consumer. Each producer, or a client thread, will deliver a chain of packets
    to the queue. A single consumer will remove packets from the queue one at a
    time and forward it to the registered target/action. This object may be used
    by an IONetworkController on the output (transmit) side to handle the output
    packet flow downstream from an IONetworkInterface, and then call the driver's
    output function. IOOutputQueue is an abstract class that provides an interface
    for its subclasses. Concrete subclasses will complete the implementation, and
    specify the context that the target is called for packets removed from
    the queue. */

class IOOutputQueue : public OSObject
{
    OSDeclareAbstractStructors( IOOutputQueue )

private:

    static void runServiceThread(thread_call_param_t, thread_call_param_t);

protected:

    thread_call_t  _callEntry;  // callout entry structure.

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *_reserved;


/*! @function init
    @abstract Initialize an IOOutputQueue object.
    @result true if initialized successfully, false otherwise. */

    virtual bool init();

/*! @function free
    @abstract Free the IOOutputQueue object.
    @discussion Release allocated resources, then call super::free(). */

    virtual void free();

/*! @function scheduleServiceThread
    @abstract Schedule a service thread callout.
    @discussion This method can be called by service() to schedule
    a thread that will call serviceThread() when it starts running.
    @param param A parameter to pass to the serviceThread() method.
    @result true if a thread callout was scheduled, false otherwise. */

    virtual bool scheduleServiceThread(void * param);

/*! @function cancelServiceThread
    @abstract Cancel any pending service thread callout.
    @result true if a previously scheduled thread callout was canceled,
    false otherwise. */

    virtual bool cancelServiceThread();

/*! @function serviceThread
    @abstract Method called by the scheduled service thread when it
    starts to run.
    @discussion Must be implemented by a subclass that calls
    scheduleServiceThread(). The default implementation does nothing.
    @param param A parameter that was given to scheduleServiceThread()
    when the service thread was scheduled. */

    virtual void serviceThread(void * param);
                                             
public:

/*! @function start
    @abstract Start up the queue.
    @discussion Called by the target to start the queue. This will allow
    packets to be removed from the queue, then delivered to the target.
    @result true if the queue was started successfully, false otherwise. */

    virtual bool start() = 0;

/*! @function stop
    @abstract Stop the queue.
    @discussion Stop the queue and prevent it from sending packets to its
    target.
    @result Returns the previous running state of the queue,
    true if the queue was running, false if the queue was already stopped. */

    virtual bool stop() = 0;

/*! @function service
    @abstract Service the queue.
    @discussion Manage the queue after it has been started.
    @param options Options for the service request.
    @result A return value to indicate the service result. */

    virtual bool service(IOOptionBits options = 0) = 0;

/*! @function flush
    @abstract Drop and free all packets currently held by the queue.
    @result The number of packets that were dropped and freed. */

    virtual UInt32 flush() = 0;

/*! @function setCapacity
    @abstract Change the number of packets that the queue can hold
    before it begins to drop excess packets.
    @param capacity The new desired capacity.
    @result true if the new capacity was accepted, false otherwise. */

    virtual bool setCapacity(UInt32 capacity) = 0;

/*! @function getCapacity
    @abstract Get the number of packets that the queue can hold.
    @discussion The queue will begin to drop incoming packets when the
    size of queue reaches its capacity.
    @result The current queue capacity. */

    virtual UInt32 getCapacity() const = 0;

/*! @function getSize
    @abstract Get the number of packets currently held in the queue.
    @result The size of the queue. */

    virtual UInt32 getSize() const = 0;

/*! @function enqueue
    @abstract Called by a client to add a packet, or a chain of packets,
    to the queue.
    @discussion A packet is described by a mbuf chain, while a chain
    of packets is constructed by linking multiple mbuf chains via the
    m_nextpkt field.
    @param m A single packet, or a chain of packets.
    @param param A parameter provided by the caller.
    @result A return code. */

    virtual UInt32 enqueue(struct mbuf * m, void * param) = 0;

/*! @function getOutputHandler
    @abstract Return the address of a function that is designated to handle
    incoming packets sent to the queue object.
    @result The address of the enqueue() method is returned. */

    virtual IOOutputAction getOutputHandler() const;

/*! @function getStatisticsData
    @abstract Return an IONetworkData object containing statistics counters
    updated by the queue.
    @result An IONetworkData object. This implementation will always return
    0. */

    virtual IONetworkData * getStatisticsData() const;

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  0);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  1);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  2);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  3);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  4);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  5);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  6);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  7);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  8);
    OSMetaClassDeclareReservedUnused( IOOutputQueue,  9);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 10);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 11);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 12);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 13);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 14);
    OSMetaClassDeclareReservedUnused( IOOutputQueue, 15);
};

#endif /* !_IOOUTPUTQUEUE_H */
