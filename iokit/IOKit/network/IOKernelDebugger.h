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
 * IOKernelDebugger.cpp
 *
 * HISTORY
 *
 */

#ifndef _IOKERNELDEBUGGER_H
#define _IOKERNELDEBUGGER_H

#include <IOKit/IOService.h>

/*! @typedef IODebuggerRxHandler
    @discussion Defines the receive handler that must be implemented
    by the target to service KDP receive requests. This handler is called
    by kdpReceiveDispatcher().
    @param target The target object.
    @param buffer KDP receive buffer. The buffer allocated has room for
           1518 bytes. The receive handler must not overflow this buffer.
    @param length The amount of data received and placed into the buffer.
           Set to 0 if no frame was received during the poll interval.
    @param timeout The amount of time to poll in milliseconds while waiting
           for a frame to arrive. */

typedef void (*IODebuggerRxHandler)( IOService * target,
                                     void *      buffer,
                                     UInt32 *    length,
                                     UInt32      timeout );

/*! @typedef IODebuggerTxHandler
    @discussion Defines the transmit handler that must be implemented
    by the target to service KDP transmit requests. This handler is called
    by kdpTransmitDispatcher().
    @param target The target object.
    @param buffer KDP transmit buffer. This buffer contains a KDP frame
           to be sent on the network.
    @param length The number of bytes in the transmit buffer. */

typedef void (*IODebuggerTxHandler)( IOService * target,
                                     void *      buffer,
                                     UInt32      length );

/*! @typedef IODebuggerLockState
    @discussion Defines flags returned by IOKernelDebugger::lock().
    @constant kIODebuggerLockTaken Set if the debugger lock was taken. */

typedef enum {
    kIODebuggerLockTaken = 0x1,
} IODebuggerLockState;

/*! class IOKernelDebugger : public IOService
    @abstract Kernel debugger nub.
    @discussion This object interfaces with the KDP
    (kernel debugger protocol) module and dispatches KDP requests to its
    target (provider). The target, designated as the debugger device, must 
    implement a pair of handler functions that are called to handle KDP 
    transmit and receive requests during a debugging session. Only a single
    IOKernelDebugger in the system can be active at a given time. The
    active IOKernelDebugger is the one that has an IOKDP object attached
    as a client.

    The debugger device is usually a subclass of IOEthernetController.
    However, any IOService can service an IOKernelDebugger client,
    implement the two polled mode handlers, and transport the KDP
    packets through a data channel. However, KDP assumes that the
    debugger device is an Ethernet interface and therefore it will
    always send, and expect to receive, an Ethernet frame. */

class IOKernelDebugger : public IOService
{
    OSDeclareDefaultStructors( IOKernelDebugger )

protected:
    IOService *            _target;      // target (provider)
    IODebuggerTxHandler    _txHandler;   // target's transmit handler.
    IODebuggerRxHandler    _rxHandler;   // target's receive handler.
    IOService *            _client;      // client that has opened us.
    bool                   _pmDisabled;  // true if disabled by PM.

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *	    _reserved;


    static void pmEnableDebugger(  IOKernelDebugger * debugger );
    static void pmDisableDebugger( IOKernelDebugger * debugger );

/*! @function kdpReceiveDispatcher
    @abstract The KDP receive dispatch function.
    @discussion Field KDP receive requests, then dispatches the call to the
    registered receiver handler.
    @param buffer KDP receive buffer. The buffer allocated by KDP has room
           for 1518 bytes. The receive handler must not overflow this buffer.
    @param length The amount of data received and placed into the buffer.
           Set to 0 if a frame was not received during the poll interval.
    @param timeout The amount of time to poll in milliseconds while waiting
           for a frame to arrive. */

    static void kdpReceiveDispatcher(void *   buffer,
                                     UInt32 * length,
                                     UInt32   timeout);

/*! @function kdpTransmitDispatcher
    @abstract The KDP transmit dispatch function.
    @discussion Field KDP transmit requests, then dispatches the call to the
    registered transmit handler.
    @param buffer KDP transmit buffer. This buffer contains a KDP frame to
           be sent on the network.
    @param length The number of bytes in the transmit buffer. */

    static void kdpTransmitDispatcher(void * buffer, UInt32 length);

/*! @function free
    @abstract Free the IOKernelDebugger instance. */

    virtual void free();

/*! @function nullTxHandler
    @abstract Null transmit handler.
    @discussion This function is registered as the transmit handler when an
    IOKernelDebugger object surrenders its status as the active debugger nub.
    Until another IOKernelDebugger object gets promoted, this function will
    handle polled transmit requests from KDP. This function does nothing
    useful. */

    static void nullTxHandler( IOService * target,
                               void *      buffer,
                               UInt32      length );

/*! @function nullRxHandler
    @abstract Null receive handler.
    @discussion This function is registered as the receive handler when an
    IOKernelDebugger object surrenders its status as the active debugger nub.
    Until another IOKernelDebugger object gets promoted, this function will
    handle polled receive requests from KDP. This function does nothing
    except to log a warning message. */

    static void nullRxHandler( IOService * target,
                               void *      buffer,
                               UInt32 *    length,
                               UInt32      timeout );

/*! @function registerHandler
    @abstract Register the target and the handler functions.
    @discussion This method is called by handleOpen() and handleClose()
    to register or unregister the target and its handler functions.
    @param target The target object.
    @param txHandler The transmit handler function. The null handler is
    registered if the argument is zero.
    @param rxHandler The receive handler function. The null handler is
    registered if the argument is zero. */

    static void registerHandler( IOService *          target,
                                 IODebuggerTxHandler  txHandler = 0,
                                 IODebuggerRxHandler  rxHandler = 0 );

/*! @function powerStateWillChangeTo
    @abstract Handle notification that the network controller will change
    power state.
    @discussion If the controller is about to become unusable, then the
    controller's handlers are unregistered, and the controller disabled.
    @param flags Describe the capability of the controller in the new power 
           state.
    @param stateNumber The number of the state in the state array that the 
           controller is switching to.
    @param policyMaker The policy-maker that manages the controller's
           power state.
    @result The constant 3000000, to indicate a maximum of 3 seconds for the 
            preparation to complete, and an acknowledgement delivered to the
            policy-maker. */

    virtual IOReturn powerStateWillChangeTo( IOPMPowerFlags  flags,
                                             UInt32          stateNumber,
                                             IOService *     policyMaker );

/*! @function powerStateDidChangeTo
    @abstract Handle notification that the network controller did change
    power state.
    @discussion If the controller became usable, then the controller is 
    re-enabled, and the controller's handlers are re-registered.
    @param flags Describe the capability of the controller in the new power 
           state.
    @param stateNumber The number of the state in the state array that the 
           controller is switching to.
    @param policyMaker The policy-maker that manages the controller's
           power state.
    @result The constant 3000000, to indicate a maximum of 3 seconds for the 
            preparation to complete, and an acknowledgement delivered to the
            policy-maker. */

    virtual IOReturn powerStateDidChangeTo( IOPMPowerFlags  flags,
                                            UInt32          stateNumber,
                                            IOService *     policyMaker );

/*! @function handleOpen
    @abstract Handle a client open.
    @discussion This method is called by IOService::open() to handle an
    open from a client (IOKDP) with the arbitration lock held.
    @param forClient The client (IOKDP) requesting the open.
    @param options Options passed to the open() call. Not used.
    @param arg A family defined argument passed to the open() call. Not used.
    @result true on success, false otherwise. */

    virtual bool handleOpen( IOService *    forClient,
                             IOOptionBits   options,
                             void *         arg );

/*! @function handleClose
    @abstract Handle a client close.
    @discussion This method is called by IOService::close() to handle a
    close from a client with the arbitration lock held.
    @param forClient The client (IOKDP) requesting the close.
    @param options Options passed to the close() call. Not used. */

    virtual void handleClose( IOService *   forClient,
                              IOOptionBits  options );

/*! @function handleIsOpen
    @abstract Query whether a client has an open on this object.
    @discussion This method is called by IOService::isOpen() with the
    arbitration lock held.
    @result true if the specified client, or any client if none (0) is
    specified, presently has an open on this object. */

    virtual bool handleIsOpen( const IOService * forClient ) const;

public:

/*! @function lock
    @abstract Take the debugger lock conditionally.
    @discussion Take the debugger lock if the object given matches the
    target registered by registerHandler().
    @param target The target or provider of an IOKernelDebugger object.
    @result kIODebuggerLockTaken if the lock was taken, or 0 otherwise. */

    static IODebuggerLockState lock( IOService * target );

/*! @function unlock
    @abstract Release the debugger lock.
    @discussion Release the debugger lock if the kIODebuggerLockTaken flag is
    set in the argument. */

    static void unlock( IODebuggerLockState state );

/*! @function init
    @abstract Initialize an IOKernelDebugger instance.
    @param target The target object that implements the debugger handlers.
    @param txHandler The target's transmit handler. A pointer to a 'C' function.
    @param rxHandler The target's receive handler. A pointer to a 'C' function.
    @result true if the instance initialized successfully, false otherwise. */

    virtual bool init( IOService *          target,
                       IODebuggerTxHandler  txHandler,
                       IODebuggerRxHandler  rxHandler );

/*! @function debugger
    @abstract A factory method that performs allocation and initialization
    of an IOKernelDebugger object.
    @param target The target object that implements the debugger handlers.
    @param txHandler The target's transmit handler. A pointer to a 'C' function.
    @param rxHandler The target's receive handler. A pointer to a 'C' function.
    @result An IOKernelDebugger instance on success, 0 otherwise. */

    static IOKernelDebugger * debugger( IOService *          target,
                                        IODebuggerTxHandler  txHandler,
                                        IODebuggerRxHandler  rxHandler );

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IOKernelDebugger,  0);
    OSMetaClassDeclareReservedUnused( IOKernelDebugger,  1);
    OSMetaClassDeclareReservedUnused( IOKernelDebugger,  2);
    OSMetaClassDeclareReservedUnused( IOKernelDebugger,  3);
};

// Concise form of the lock()/unlock() static member functions.
//
#define IODebuggerLock    IOKernelDebugger::lock
#define IODebuggerUnlock  IOKernelDebugger::unlock

#endif /* !_IOKERNELDEBUGGER_H */
