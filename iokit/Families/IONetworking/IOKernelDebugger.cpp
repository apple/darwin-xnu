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
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOLocks.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/network/IOKernelDebugger.h>
#include <libkern/OSAtomic.h>

//---------------------------------------------------------------------------
// IOKDP

#define kIOKDPEnableKDP         "IOEnableKDP"
#define kIOKDPDriverMatch       "IODriverMatch"
#define kIOKDPDriverNubMatch    "IODriverNubMatch"

class IOKDP : public IOService
{
    OSDeclareDefaultStructors( IOKDP )

public:
    static void  initialize();

    virtual bool start( IOService * provider );

    virtual void stop( IOService * provider );

    virtual bool matchProvider( IOService * provider );

    virtual bool matchServiceWithDictionary( IOService *    service,
                                             OSDictionary * match );

    virtual IOReturn message( UInt32       type,
                              IOService *  provider,
                              void *       argument = 0 );
};

//---------------------------------------------------------------------------
// IOKDP defined globals.

static IOLock * gIOKDPLock = 0;
static IOKDP *  gIOKDP     = 0;

#define super IOService
OSDefineMetaClassAndStructorsWithInit( IOKDP, IOService,
                                       IOKDP::initialize() )

//---------------------------------------------------------------------------
// Match the provider with the matching dictionary in our property table.

bool IOKDP::matchProvider(IOService * provider)
{
    IOService * driver    = 0;
    IOService * driverNub = 0;
    OSBoolean * aBool;

    if ( provider )  driver = provider->getProvider();
    if ( driver ) driverNub = driver->getProvider();

    if ( (driver == 0) || (driverNub == 0) )
        return false;

    if ( ( aBool = OSDynamicCast(OSBoolean, getProperty(kIOKDPEnableKDP)) ) &&
         ( aBool->isTrue() == false ) )
        return false;

    if ( matchServiceWithDictionary( driver, (OSDictionary *)
                                     getProperty(kIOKDPDriverMatch)) )
    {
        // IOLog("IOKDP: %s\n", kIOKDPDriverMatch);
        return true;
    }

    if ( matchServiceWithDictionary( driverNub, (OSDictionary *) 
                                     getProperty(kIOKDPDriverNubMatch)) )
    {
        // IOLog("IOKDP: %s\n", kIOKDPDriverNubMatch);
        return true;
    }

    return false;
}

//---------------------------------------------------------------------------
// Match an IOService with a matching dictionary.

bool IOKDP::matchServiceWithDictionary(IOService *    service,
                                       OSDictionary * match)
{
    OSCollectionIterator * matchIter;
    OSCollectionIterator * arrayIter = 0;
    OSCollection *         array;
    OSObject *             objM;
    OSObject *             objP;
    OSSymbol *             sym;
    bool                   isMatch = false;

    if ( ( OSDynamicCast(OSDictionary, match) == 0 ) ||
         ( match->getCount() == 0 )                  ||
         ( (matchIter = OSCollectionIterator::withCollection(match)) == 0 ) )
        return false;

    while ( ( sym = OSDynamicCast(OSSymbol, matchIter->getNextObject()) ) )
    {
        objM = match->getObject(sym);
        objP = service->getProperty(sym);

        isMatch = false;

        if ( arrayIter )
        {
            arrayIter->release();
            arrayIter = 0;
        }

        if ( (array = OSDynamicCast( OSCollection, objM )) )
        {
            arrayIter = OSCollectionIterator::withCollection( array );
            if ( arrayIter == 0 ) break;
        }

        do {
            if ( arrayIter && ((objM = arrayIter->getNextObject()) == 0) )
                break;

            if ( objM && objP && objM->isEqualTo(objP) )
            {
                isMatch = true;
                break;
            }
        }
        while ( arrayIter );

        if ( isMatch == false ) break;
    }

    if ( arrayIter ) arrayIter->release();
    matchIter->release();

    return isMatch;
}

//---------------------------------------------------------------------------
// IOKDP class initializer.

void IOKDP::initialize()
{
    gIOKDPLock = IOLockAlloc();
    assert( gIOKDPLock );
}

//---------------------------------------------------------------------------
// start/stop/message.

bool IOKDP::start( IOService * provider )
{
    bool ret = false;

    if ( super::start(provider) == false )
        return false;

    IOLockLock( gIOKDPLock );

    do {
        if ( gIOKDP )
            break;

        if ( matchProvider(provider) == false )
            break;

        if ( provider->open(this) == false )
            break;

        publishResource("kdp");

        gIOKDP = this;
        ret    = true;
    }
    while ( false );

    IOLockUnlock( gIOKDPLock );

    return ret;
}

void IOKDP::stop( IOService * provider )
{
    provider->close(this);

    IOLockLock( gIOKDPLock );

    if ( gIOKDP == this ) gIOKDP = 0;

    IOLockUnlock( gIOKDPLock );

    super::stop(provider);
}

IOReturn IOKDP::message( UInt32       type,
                         IOService *  provider,
                         void *       argument )
{
    if ( type == kIOMessageServiceIsTerminated )
    {
        provider->close(this);
    }
    return kIOReturnSuccess;
}


//---------------------------------------------------------------------------
// IOKernelDebugger

extern "C" {
//
// Defined in osfmk/kdp/kdp_en_debugger.h, but the header file is not
// exported, thus the definition is replicated here.
//
typedef void (*kdp_send_t)( void * pkt, UInt pkt_len );
typedef void (*kdp_receive_t)( void * pkt, UInt * pkt_len, UInt timeout );
void kdp_register_send_receive( kdp_send_t send, kdp_receive_t receive );
}

#undef  super
#define super IOService
OSDefineMetaClassAndStructors( IOKernelDebugger, IOService )
OSMetaClassDefineReservedUnused( IOKernelDebugger,  0);
OSMetaClassDefineReservedUnused( IOKernelDebugger,  1);
OSMetaClassDefineReservedUnused( IOKernelDebugger,  2);
OSMetaClassDefineReservedUnused( IOKernelDebugger,  3);

// IOKernelDebugger global variables.
//
IOService *          gIODebuggerDevice    = 0;
IODebuggerTxHandler  gIODebuggerTxHandler = 0;
IODebuggerRxHandler  gIODebuggerRxHandler = 0;
UInt32               gIODebuggerTxBytes   = 0;
UInt32               gIODebuggerRxBytes   = 0;
SInt32               gIODebuggerSemaphore = 0;
UInt32               gIODebuggerFlag      = 0;

// Global debugger flags.
// 
enum {
    kIODebuggerFlagRegistered       = 0x01,
    kIODebuggerFlagWarnNullHandler  = 0x02
};

//---------------------------------------------------------------------------
// The KDP receive dispatch function. Dispatches KDP receive requests to the
// registered receive handler. This function is registered with KDP via 
// kdp_register_send_receive().

void IOKernelDebugger::kdpReceiveDispatcher( void *   buffer,
                                             UInt32 * length, 
                                             UInt32   timeout )
{
    *length = 0;    // return a zero length field by default.

    if ( gIODebuggerSemaphore ) return;  // FIXME - Driver is busy!

    (*gIODebuggerRxHandler)( gIODebuggerDevice, buffer, length, timeout );

    gIODebuggerRxBytes += *length;
}

//---------------------------------------------------------------------------
// The KDP transmit dispatch function. Dispatches KDP receive requests to the
// registered transmit handler. This function is registered with KDP via 
// kdp_register_send_receive().

void IOKernelDebugger::kdpTransmitDispatcher( void * buffer, UInt32 length )
{
    if ( gIODebuggerSemaphore ) return;  // FIXME - Driver is busy!

    (*gIODebuggerTxHandler)( gIODebuggerDevice, buffer, length );

    gIODebuggerTxBytes += length;
}

//---------------------------------------------------------------------------
// Null debugger handlers.

void IOKernelDebugger::nullTxHandler( IOService * target,
                                      void *      buffer,
                                      UInt32      length )
{
}

void IOKernelDebugger::nullRxHandler( IOService * target,
                                      void *      buffer,
                                      UInt32 *    length,
                                      UInt32      timeout )
{
    if ( gIODebuggerFlag & kIODebuggerFlagWarnNullHandler )
    {
        IOLog("IOKernelDebugger::%s no debugger device\n", __FUNCTION__);
        gIODebuggerFlag &= ~kIODebuggerFlagWarnNullHandler;
    }
}

//---------------------------------------------------------------------------
// Take the debugger lock conditionally.

IODebuggerLockState IOKernelDebugger::lock( IOService * object )
{
    if ( gIODebuggerDevice == object )
    {
        OSIncrementAtomic( &gIODebuggerSemaphore );
        return kIODebuggerLockTaken;
    }
    return (IODebuggerLockState) 0;
}

//---------------------------------------------------------------------------
// Release the debugger lock if the kIODebuggerLockTaken flag is set.

void IOKernelDebugger::unlock( IODebuggerLockState state )
{
    if ( state & kIODebuggerLockTaken )
        OSDecrementAtomic( &gIODebuggerSemaphore );
}

//---------------------------------------------------------------------------
// Initialize an IOKernelDebugger instance.

bool IOKernelDebugger::init( IOService *          target,
                             IODebuggerTxHandler  txHandler,
                             IODebuggerRxHandler  rxHandler )
{
    if ( ( super::init() == false )                ||
         ( OSDynamicCast(IOService, target) == 0 ) ||
         ( txHandler == 0 )                        ||
         ( rxHandler == 0 ) )
    {
        return false;
    }

    // Cache the target and handlers provided.

    _target     = target;
    _txHandler  = txHandler;
    _rxHandler  = rxHandler;

    return true;
}

//---------------------------------------------------------------------------
// Factory method which performs allocation and initialization of an 
// IOKernelDebugger instance.

IOKernelDebugger * IOKernelDebugger::debugger( IOService *          target,
                                               IODebuggerTxHandler  txHandler,
                                               IODebuggerRxHandler  rxHandler )
{
    IOKernelDebugger * debugger = new IOKernelDebugger;

    if (debugger && (debugger->init( target, txHandler, rxHandler ) == false))
    {
        debugger->release();
        debugger = 0;
    }

    return debugger;
}

//---------------------------------------------------------------------------
// Register the debugger handlers.

void IOKernelDebugger::registerHandler( IOService *          target,
                                        IODebuggerTxHandler  txHandler,
                                        IODebuggerRxHandler  rxHandler )
{
    bool doRegister;

    assert( ( target == gIODebuggerDevice ) ||
            ( target == 0 )                 ||
            ( gIODebuggerDevice == 0 ) );

    doRegister = ( target && ( txHandler != 0 ) && ( rxHandler != 0 ) );

    if ( txHandler == 0 ) txHandler = &IOKernelDebugger::nullTxHandler;
    if ( rxHandler == 0 ) rxHandler = &IOKernelDebugger::nullRxHandler;    

    OSIncrementAtomic( &gIODebuggerSemaphore );

    gIODebuggerDevice    = target;  
    gIODebuggerTxHandler = txHandler;
    gIODebuggerRxHandler = rxHandler;
    gIODebuggerFlag     |= kIODebuggerFlagWarnNullHandler;

    OSDecrementAtomic( &gIODebuggerSemaphore );

    if ( doRegister && (( gIODebuggerFlag & kIODebuggerFlagRegistered ) == 0) )
    {
        // Register dispatch function, these in turn will call the
        // handlers when the debugger is active.
        // 
        // Note: The following call may trigger an immediate break
        //       to the debugger.

        kdp_register_send_receive( (kdp_send_t) kdpTransmitDispatcher,
                                   (kdp_receive_t) kdpReceiveDispatcher );

        // Limit ourself to a single real KDP registration.

        gIODebuggerFlag |= kIODebuggerFlagRegistered;
    }
}

//---------------------------------------------------------------------------
// Called by open() with the arbitration lock held.

bool IOKernelDebugger::handleOpen( IOService *    forClient,
                                   IOOptionBits   options,
                                   void *         arg )
{
    IONetworkController * ctr = OSDynamicCast(IONetworkController, _target);
    bool                  ret = false;

    do {
        // Only a single client at a time.

        if ( _client ) break;

        // Register the target to prime the lock()/unlock() functionality
        // before opening the target.

        registerHandler( _target );

        // While the target is opened/enabled, it must block any thread
        // which may acquire the debugger lock in its execution path.

        if ( _target->open( this ) == false )
            break;

        // Register interest in receiving notifications about controller
        // power state changes.
        //
        // We are making an assumption that the controller is 'usable' and
        // the next notification will inform this object that the controller
        // has become unusable, there is no support for cases when the
        // controller is already in an 'unusable' state.

        _pmDisabled = false;

        if ( ctr )
        {
            // Register to receive PM notifications for controller power
            // state changes.

            ctr->registerInterestedDriver( this );
        
            if ( ctr->doEnable( this ) != kIOReturnSuccess )
            {
                ctr->deRegisterInterestedDriver( this );
                break;
            }
        }

        // After the target has been opened, complete the registration.

        IOLog("%s: Debugger attached\n", getName());
        registerHandler( _target, _txHandler, _rxHandler );

        // Remember the client.

        _client = forClient;

        ret = true;
    }
    while (0);

    if ( ret == false )
    {
        registerHandler( 0 );
        _target->close( this );
    }

    return ret;
}

//---------------------------------------------------------------------------
// Called by IOService::close() with the arbitration lock held.

void IOKernelDebugger::handleClose( IOService *   forClient,
                                    IOOptionBits  options )
{
    IONetworkController * ctr = OSDynamicCast(IONetworkController, _target);

    if ( _client && ( _client == forClient ) )
    {
        // There is no KDP un-registration. The best we can do is to
        // register dummy handlers.

        registerHandler( 0 );

        if ( ctr )
        {
            // Disable controller if it is not already disabled.

            if ( _pmDisabled == false )
            {
                ctr->doDisable( this );
            }

            // Before closing the controller, remove interest in receiving
            // notifications about controller power state changes.

            ctr->deRegisterInterestedDriver( this );
        }

        _client = 0;

        _target->close( this );
    }
}

//---------------------------------------------------------------------------
// Called by IOService::isOpen() with the arbitration lock held.

bool IOKernelDebugger::handleIsOpen( const IOService * forClient ) const
{
    if ( forClient == 0 )
        return ( forClient != _client );
    else
        return ( forClient == _client );
}

//---------------------------------------------------------------------------
// Free the IOKernelDebugger object.

void IOKernelDebugger::free()
{
    // IOLog("IOKernelDebugger::%s %p\n", __FUNCTION__, this);
    super::free();
}

#define PM_SECS(x)    ((x) * 1000 * 1000)

//---------------------------------------------------------------------------
// Handle controller's power state change notitifications.

IOReturn
IOKernelDebugger::powerStateWillChangeTo( IOPMPowerFlags  flags,
                                          unsigned long   stateNumber,
                                          IOService *     policyMaker )
{
    IOReturn ret = IOPMAckImplied;

    if ( ( flags & IOPMDeviceUsable ) == 0 )
    {
        // Controller is about to transition to an un-usable state.
        // The debugger nub should be disabled.

        this->retain();

        thread_call_func( (thread_call_func_t) pmDisableDebugger,
                          this,    /* parameter */
                          FALSE ); /* disable unique call filter */

        ret = PM_SECS(3);  /* Must ACK within 3 seconds */
    }

    return ret;
}

IOReturn
IOKernelDebugger::powerStateDidChangeTo( IOPMPowerFlags  flags,
                                         unsigned long   stateNumber,
                                         IOService *     policyMaker )
{
    IOReturn ret = IOPMAckImplied;

    if ( flags & IOPMDeviceUsable )
    {
        // Controller has transitioned to an usable state.
        // The debugger nub should be enabled if necessary.

        this->retain();

        thread_call_func( (thread_call_func_t) pmEnableDebugger,
                          this,    /* parameter */
                          FALSE ); /* disable unique call filter */

        ret = PM_SECS(3);  /* Must ACK within 3 seconds */
    }

    return ret;
}

//---------------------------------------------------------------------------
// Static member function: Enable the debugger nub after the controller
// transitions into an usable state.

void IOKernelDebugger::pmEnableDebugger( IOKernelDebugger * debugger )
{
    IONetworkController * ctr;
    assert( debugger );

    ctr = OSDynamicCast( IONetworkController, debugger->_target );

    debugger->lockForArbitration();

    if ( debugger->_client && ( debugger->_pmDisabled == true ) )
    {
        if ( ctr && ( ctr->doEnable( debugger ) != kIOReturnSuccess ) )
        {
            // This is bad, unable to re-enable the controller after sleep.
            IOLog("IOKernelDebugger: Unable to re-enable controller\n");
        }
        else
        {
            registerHandler( debugger->_target, debugger->_txHandler, 
                                                debugger->_rxHandler );

            debugger->_pmDisabled = false;
        }
    }

    debugger->unlockForArbitration();

    // Ack the power state change.
    debugger->_target->acknowledgePowerChange( debugger );

    debugger->release();
}

//---------------------------------------------------------------------------
// Static member function: Disable the debugger nub before the controller
// transitions into an unusable state.

void IOKernelDebugger::pmDisableDebugger( IOKernelDebugger * debugger )
{
    IONetworkController * ctr;
    assert( debugger );

    ctr = OSDynamicCast( IONetworkController, debugger->_target );

    debugger->lockForArbitration();

    if ( debugger->_client && ( debugger->_pmDisabled == false ) )
    {
        // Keep an open on the controller, but inhibit access to the
        // controller's debugger handlers, and disable controller's
        // hardware support for the debugger.

        registerHandler( 0 );
        if ( ctr ) ctr->doDisable( debugger );

        debugger->_pmDisabled = true;
    }

    debugger->unlockForArbitration();

    // Ack the power state change.
    debugger->_target->acknowledgePowerChange( debugger );

    debugger->release();
}
