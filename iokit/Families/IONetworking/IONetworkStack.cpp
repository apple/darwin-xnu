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
 * IONetworkStack.cpp - An IOKit proxy for the BSD network stack.
 *
 * HISTORY
 *
 * IONetworkStack abstracts essential network stack services. These
 * include registering/unregistering network interfaces, and interface
 * name space management.
 *
 * Only a single IONetworkStack object is instantiated. This object will
 * register to receive a notification when a network interface object is
 * first published. The notification handler is responsible for attaching
 * the network stack object to the interface object as a client. When the
 * interface is terminated, this linkage is severed.
 *
 * This object does not participate in the data/packet flow. The interface
 * object will interact directly with DLIL to send and to receive packets.
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IONetworkStack.h>
#include <libkern/c++/OSDictionary.h>

extern "C" {
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/dlil.h>
#include <sys/sockio.h>
void ether_ifattach(struct ifnet * ifp);   // FIXME
}

#define super IOService
OSDefineMetaClassAndStructors( IONetworkStack, IOService )
OSMetaClassDefineReservedUnused( IONetworkStack,  0);
OSMetaClassDefineReservedUnused( IONetworkStack,  1);
OSMetaClassDefineReservedUnused( IONetworkStack,  2);
OSMetaClassDefineReservedUnused( IONetworkStack,  3);

#ifdef  DEBUG_XXX
#define __LOG(class, fn, fmt, args...)   IOLog(class "::%s " fmt, fn, ## args)
#define DLOG(fmt, args...) __LOG("IONetworkStack", __FUNCTION__, fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

#define NETIF_FLAGS(n)           ((n)->_clientVar[0])
#define SET_NETIF_FLAGS(n, x)    (NETIF_FLAGS(n) |= (x))
#define CLR_NETIF_FLAGS(n, x)    (NETIF_FLAGS(n) &= ~(x))

static IONetworkStack * gIONetworkStack = 0;

// Flags encoded on the interface object.
//
enum {
    kInterfaceFlagActive      = 0x01,  // Interface is awaiting registration
    kInterfaceFlagRegistered  = 0x02,  // Interface has registered with DLIL
    kInterfaceFlagRegistering = 0x04   // Interface is registering with DLIL
};

// IONetworkStackUserClient definition.
//
#include <IOKit/IOUserClient.h>

class IONetworkStackUserClient : public IOUserClient
{
    OSDeclareDefaultStructors( IONetworkStackUserClient )

protected:
    IONetworkStack * _provider;

public:
    static  IONetworkStackUserClient * withTask( task_t owningTask );
    virtual bool start( IOService * provider );
    virtual IOReturn clientClose();
    virtual IOReturn clientDied();
    virtual IOReturn setProperties( OSObject * properties );
};

//---------------------------------------------------------------------------
// Initialize the IONetworkStack object.

bool IONetworkStack::init( OSDictionary * properties )
{
    // Init our superclass first.

    if ( super::init(properties) == false )
        return false;

    return true;
}

//---------------------------------------------------------------------------
// IONetworkStack was matched to its provider (IOResources), now start it up.

bool IONetworkStack::start( IOService * provider )
{
    DLOG("%p\n", provider);

    if ( super::start(provider) == false )
        return false;

    // Only a single IONetworkStack object is created, and a reference
    // to this object is stored in a global variable.

    // When the boot process is VERY VERY slow for some unknown reason
    // we get two instances of IONetworkStack and theassert below fires.
    // so I am commenting the assert and replacing it with an if statement.
    // assert( gIONetworkStack == 0 );

    if ( gIONetworkStack != 0 )
        return false;

    gIONetworkStack = this;

    // Create containers to store interface objects.

    _ifSet = OSOrderedSet::withCapacity(10);
    if ( _ifSet == 0 )
        return false;

    _ifDict = OSDictionary::withCapacity(4);
    if ( _ifDict == 0 )
        return false;

    // Create a notification object to call a 'C' function, every time an
    // interface object is first published.

    _interfaceNotifier = addNotification(
                         /* type   */    gIOFirstPublishNotification,
                         /* match  */    serviceMatching("IONetworkInterface"),
                         /* action */    interfacePublished,
                         /* param  */    this );

    if ( _interfaceNotifier == 0 ) return false;

    // Register the IONetworkStack object.

    registerService();

    // Success.

    DLOG("success\n");

    return true;
}

//---------------------------------------------------------------------------
// Stop is called by a terminated provider, after being closed, but before
// this client object is detached from it.

void IONetworkStack::stop( IOService * provider )
{
    DLOG("%p\n", provider);
    super::stop(provider);
}

//---------------------------------------------------------------------------
// Release allocated resources.

void IONetworkStack::free()
{
    DLOG("\n");

    // IONotifier::remove() will remove the notification request
    // and release the object.

    if ( _interfaceNotifier )
    {
        _interfaceNotifier->remove();
        _interfaceNotifier = 0;
    }

    // Free interface containers.

    if ( _ifDict )
    {
        _ifDict->release();
        _ifDict = 0;
    }

    if ( _ifSet )
    {
        _ifSet->release();
        _ifSet = 0;
    }

    gIONetworkStack = 0;

    // Propagate the free to superclass.

    super::free();
}

//---------------------------------------------------------------------------
// A static method to get the global network stack object.

IONetworkStack * IONetworkStack::getNetworkStack()
{
    return (IONetworkStack *) IOService::waitForService(
                              IOService::serviceMatching("IONetworkStack") );
}


//===========================================================================
//
// Interface object container helpers.
//
//===========================================================================

//---------------------------------------------------------------------------
// Add the new interface object to an OSOrderedSet.

bool IONetworkStack::addInterface( IONetworkInterface * netif )
{
    return _ifSet->setObject(netif);
}

//---------------------------------------------------------------------------
// Remove an interface object from an OSOrderedSet.

void IONetworkStack::removeInterface( IONetworkInterface * netif )
{
    _ifSet->removeObject(netif);
    DLOG("count = %d\n", _ifSet->getCount());
}

//---------------------------------------------------------------------------
// Get an interface object at a given index.

IONetworkInterface * IONetworkStack::getInterface( UInt32 index )
{
    return (IONetworkInterface *) _ifSet->getObject(index);
}

//---------------------------------------------------------------------------
// Query whether the specified interface object is a member of the Set.

bool IONetworkStack::containsInterface( IONetworkInterface * netif )
{
    return _ifSet->containsObject(netif);
}

//---------------------------------------------------------------------------
// Add an interface object to the set of registered interfaces.

bool IONetworkStack::addRegisteredInterface( IONetworkInterface * netif )
{
    bool           success = true;
    OSOrderedSet * set;
    const char *   prefix = netif->getNamePrefix();

    if (prefix == 0) return false;

    // Look for a Set object in the dictionary.

    set = (OSOrderedSet *) _ifDict->getObject(prefix);

    // If not found, then create one and add it to the dictionary.

    if ( (set == 0) &&
         ((set = OSOrderedSet::withCapacity(10, orderRegisteredInterfaces))) )
    {
        success = _ifDict->setObject(prefix, set);
        set->release();
    }

    // Add the interface object to its corresponding set.
    // All objects in a set will have the same name prefix.

    success = (set && success) ? set->setObject(netif) : false;

    return success;
}

//---------------------------------------------------------------------------
// Remove an interface object from the set of registered interfaces.

void IONetworkStack::removeRegisteredInterface( IONetworkInterface * netif )
{
    OSOrderedSet * set;
    const char *   prefix = netif->getNamePrefix();

    if ( prefix )
    {
        set = (OSOrderedSet *) _ifDict->getObject(prefix);

        if ( set )
        {
            // Remove interface from set.

            set->removeObject(netif);
            DLOG("set:%s count = %d\n", prefix, set->getCount());

            // Remove (also release) the set from the dictionary.

            if ( set->getCount() == 0 ) _ifDict->removeObject(prefix);
        }
    }
}

//---------------------------------------------------------------------------
// Get an registered interface with the given prefix and unit number.

IONetworkInterface *
IONetworkStack::getRegisteredInterface( const char * prefix,
                                        UInt32       unit )
{
    OSOrderedSet *       set;
    IONetworkInterface * netif = 0;

    set = (OSOrderedSet *) _ifDict->getObject(prefix);

    for ( UInt32 index = 0;
          ( set && (netif = (IONetworkInterface *) set->getObject(index)) );
          index++ )
    {
        if ( netif->getUnitNumber() == unit )
            break;
    }

    return netif;
}

//---------------------------------------------------------------------------
// Get the last object (with largest index) in the set of registered
// interfaces with the specified prefix.

IONetworkInterface *
IONetworkStack::getLastRegisteredInterface( const char * prefix )
{
    OSOrderedSet * set;

    set = (OSOrderedSet *) _ifDict->getObject(prefix);

    return ( set ) ? (IONetworkInterface *) set->getLastObject() : 0;
}

//---------------------------------------------------------------------------
// Get the next available unit number in the set of registered interfaces
// with the specified prefix.

UInt32
IONetworkStack::getNextAvailableUnitNumber( const char * prefix,
                                            UInt32       startingUnit )
{
    IONetworkInterface * netif = getLastRegisteredInterface(prefix);

    if ( ( netif == 0 ) || ( netif->getUnitNumber() < startingUnit ) )
    {
        // The unit number provided is acceptable.
    }
    else if ( netif->getUnitNumber() == startingUnit )
    {
        // Conflict, bump proposed unit number by one.
        startingUnit++;
    }
    else
    {
        OSOrderedSet * set = (OSOrderedSet *) _ifDict->getObject(prefix);

        for ( UInt32 index = 0; set; index++ )
        {
            netif = (IONetworkInterface *) set->getObject(index);

            if ( ( netif == 0 ) ||
                 ( netif->getUnitNumber() > startingUnit ) )
                break;
            else if ( netif->getUnitNumber() < startingUnit )
                continue;
            else
                startingUnit = netif->getUnitNumber() + 1;
        }
    }

    return startingUnit;
}


//===========================================================================
//
// Interface Management.
//
//===========================================================================


//---------------------------------------------------------------------------
// A static member function that is called by a notification object when an 
// interface is published. This function is called with arbitration lock of
// the interface object held.

bool IONetworkStack::interfacePublished( void *      /* target */,
                                         void *      /* param  */,
                                         IOService * service )
{
    IONetworkInterface * netif   = OSDynamicCast(IONetworkInterface, service);
    bool                 success = false;

    DLOG("%p\n", netif);

    if ( gIONetworkStack == 0 )
        return false;

    gIONetworkStack->lockForArbitration();

    do {
        if ( netif == 0 ) break;

        // Early exit from redundant notifications.

        if ( gIONetworkStack->containsInterface(netif) == true )
        {
            success = true;
            break;
        }

        // Add the interface to a collection.

        if ( gIONetworkStack->addInterface(netif) == false )
            break;

        // Attach the stack object to the interface object as its client.

        if ( gIONetworkStack->attach(netif) == false )
            break;

        // Initialize the interface flags. These flags are used only
        // by IONetworkStack.

        NETIF_FLAGS(netif) = kInterfaceFlagActive;

        // No outside intervention is required for the primary interface
        // to be registered at unit 0. This is to assure that we have 'en0'
        // even if something is really fouled up. Ideally, this should be
        // removed in the future and have a single entity manage the
        // naming responsibility. And on Intel, there is no concept of a
        // "built-in" interface, so this will do nothing for Intel.

        if ( gIONetworkStack->_registerPrimaryInterface &&
             netif->isPrimaryInterface() )
        {
            const char * prefix = netif->getNamePrefix();
            const UInt32 unit   = 0;

            // If another interface already took unit 0, do nothing.

            if ( gIONetworkStack->getRegisteredInterface(prefix, unit) == 0 )
            {
                OSArray * array = OSArray::withCapacity(1);
                if ( array )
                {
                    gIONetworkStack->preRegisterInterface( netif,
                                                           prefix,
                                                           unit,
                                                           array );

                    completeRegistration( array, false );   // Async
                }
            }
        }

        success = true;
    }
    while ( false );

    // Remove interface on failure.

    if (success == false) gIONetworkStack->removeInterface(netif);

    gIONetworkStack->unlockForArbitration();

    return success;
}

//---------------------------------------------------------------------------
// Handle termination messages sent from the interface object (provider).

IOReturn IONetworkStack::message( UInt32      type,
                                  IOService * provider,
                                  void *      /* argument */ )
{
    IONetworkInterface * netif = (IONetworkInterface *) provider;
    IOReturn             ret   = kIOReturnBadArgument;

    DLOG("%lx %p\n", type, provider);

    if ( type == kIOMessageServiceIsTerminated )
    {
        lockForArbitration();

        do {
            // Verify that the provider object given is known.

            if ( containsInterface(netif) == false )
                break;

            ret = kIOReturnSuccess;

            // Interface has become inactive, it is no longer possible
            // to open or to attach to the interface object.
            // Mark the interface as Inactive.

            CLR_NETIF_FLAGS( netif, kInterfaceFlagActive );

            // Interface is registering with DLIL. Postpone termination until
            // the interface has completed the registration.

            if ( NETIF_FLAGS(netif) & kInterfaceFlagRegistering )
                break;

            // Remove the interface object. Don't worry, it is still retained.

            removeInterface(netif);

            // If interface was never registered with BSD, no additional
            // action is required.

            if ( (NETIF_FLAGS(netif) & kInterfaceFlagRegistered) == 0 )
                break;

            // Need to unregister the interface. Do this asynchronously.
            // The interface will be waiting for a close before advancing
            // to the next stage in the termination process.

            thread_call_func( (thread_call_func_t) unregisterBSDInterface,
                              netif,
                              TRUE );  /* unique call desired */
        }
        while ( false );

        unlockForArbitration();
    }

    return ret;
}

//---------------------------------------------------------------------------
// Detach an inactive interface that is currently registered with BSD.

void IONetworkStack::unregisterBSDInterface( IONetworkInterface * netif ) 
{
    assert( netif );

    // If dlil_if_detach() returns DLIL_WAIT_FOR_FREE, then we
    // must not close the interface until we receive a callback
    // from DLIL. Otherwise, proceed with the close.

    DLOG("%p\n", netif);

    if ( dlil_if_detach(netif->getIfnet()) != DLIL_WAIT_FOR_FREE )
    {
        bsdInterfaceWasUnregistered( netif->getIfnet() );
    }
}

//---------------------------------------------------------------------------
// Handle a callback from DLIL to signal that an interface can now be safely
// destroyed. DLIL will issue this call only if the dlil_if_detach() function
// returned DLIL_WAIT_FOR_FREE.

int IONetworkStack::bsdInterfaceWasUnregistered( struct ifnet * ifp )
{
    IONetworkInterface * netif;

    assert( ifp );

    netif = (IONetworkInterface *) ifp->if_private;
    DLOG("%p\n", netif);

    assert( netif && gIONetworkStack );

    // An interface was detached from DLIL. It is now safe to close the 
    // interface object.

    gIONetworkStack->lockForArbitration();

    assert( NETIF_FLAGS(netif) == kInterfaceFlagRegistered );

    // Update state.

    CLR_NETIF_FLAGS( netif, kInterfaceFlagRegistered );

    // Drop interface from list of registered interfaces,
    // and decrement interface retain count.

    gIONetworkStack->removeRegisteredInterface(netif);

    gIONetworkStack->unlockForArbitration();

    // Make sure the interface is brought down before it is closed.

    netif->setFlags( 0, IFF_UP );  // clear IFF_UP flag.
    (*ifp->if_ioctl)(ifp, SIOCSIFFLAGS, 0);

    // Close interface and allow it to proceed with termination.

    netif->close(gIONetworkStack);

    return 0;
}

//---------------------------------------------------------------------------
// Pre-register a network interface. This function assumes that the
// caller is holding the arbitration lock.

bool IONetworkStack::preRegisterInterface( IONetworkInterface * netif,
                                           const char *         prefix,
                                           UInt32               unit,
                                           OSArray *            array )
{
    bool success = false;

    DLOG("%p %s %d\n", netif, prefix ? prefix : "", unit);

    assert( netif && array );

    do {
        if ( prefix == 0 ) break;

        // Verify that the interface object given is known.

        if ( containsInterface(netif) == false )
            break;

        // Interface must be in Active state.

        if ( NETIF_FLAGS(netif) != kInterfaceFlagActive )
        {
            break;
        }

        // The unit argument provided is a hint to indicate the lowest unit
        // number that can be assigned to the interface. We are allowed to
        // increment the unit number provided if the number is already
        // taken.

        unit = getNextAvailableUnitNumber(prefix, unit);

        // Open the interface object. This will fail if the interface
        // object has become inactive. Beware of reverse lock acquisition
        // sequence, which is interface then stack arbitration lock.
        // Must avoid taking locks in that order to avoid deadlocks.
        // The only exception is when handling the "First Publish"
        // notification, which is safe since the stack object does not
        // yet have a reference to the new interface.

        if ( netif->open(this) == false )
        {
            break;
        }

        // Update interface name properties and add the interface object
        // to a collection of registered interfaces. The chosen name will
        // be reserved until the interface is removed from the collection
        // of registered interfaces.

        if ( ( netif->setUnitNumber(unit) == false    ) ||
             ( addRegisteredInterface(netif) == false ) )
        {
            netif->close(this);
            break;
        }

        success = true;
    }
    while ( false );

    if ( success )
    {
        // Mark the interface as in the process of registering.

        SET_NETIF_FLAGS( netif, kInterfaceFlagRegistering );

        // Add interface to pre-registration array.
        // We assume the array has enough storage space for the new entry.

        success = array->setObject( netif );
        assert( success );
    }

    return success;
}

//---------------------------------------------------------------------------
// Complete the registration of interface objects stored in the array provided.
// The arbitration lock should not be held when the 'isSync' flag is true.

void
IONetworkStack::completeRegistration( OSArray * array, bool isSync )
{
    if ( isSync )
    {
        completeRegistrationUsingArray( array );
    }
    else
    {
        thread_call_func( (thread_call_func_t) completeRegistrationUsingArray,
                          array,
                          TRUE );  /* unique call desired */
    }
}

void
IONetworkStack::completeRegistrationUsingArray( OSArray * array )
{
    IONetworkInterface * netif;

    assert( array );

    for ( UInt32 i = 0; i < array->getCount(); i++ )
    {
        netif = (IONetworkInterface *) array->getObject(i);
        assert( netif );

        registerBSDInterface( netif );
    }

    array->release();   // consumes a ref count
}

//---------------------------------------------------------------------------
// Call DLIL functions to register the BSD interface.

void IONetworkStack::registerBSDInterface( IONetworkInterface * netif )
{
    char  ifname[20];
    bool  doTermination = false;

    assert( netif );

    // Attach the interface to DLIL.

    bpfattach( netif->getIfnet(), DLT_EN10MB, sizeof(struct ether_header) );
    ether_ifattach( netif->getIfnet() );

    // Add a kIOBSDNameKey property to the interface AFTER the interface
    // has registered with DLIL. The order is very important to avoid
    // rooting from an interface which is not yet known by BSD.

    sprintf(ifname, "%s%d", netif->getNamePrefix(), netif->getUnitNumber());
    netif->setProperty(kIOBSDNameKey, ifname);

    // Update state bits and detect for untimely interface termination.

    gIONetworkStack->lockForArbitration();

    assert( ( NETIF_FLAGS(netif) &
            ( kInterfaceFlagRegistering | kInterfaceFlagRegistered ) ) ==
              kInterfaceFlagRegistering );

    CLR_NETIF_FLAGS( netif, kInterfaceFlagRegistering );
    SET_NETIF_FLAGS( netif, kInterfaceFlagRegistered  );

    if ( ( NETIF_FLAGS(netif) & kInterfaceFlagActive ) == 0 )
    {
        doTermination = true;
    }
    else
    {
        // Re-register interface after the interface has registered with BSD.
        // Is there a danger in calling registerService while holding the
        // gIONetworkStack's arbitration lock?

        netif->registerService();
    }

    gIONetworkStack->unlockForArbitration();

    // In the unlikely event that an interface was terminated before
    // being registered, re-issue the termination message and tear it
    // all down.

    if ( doTermination )
    {
        gIONetworkStack->message(kIOMessageServiceIsTerminated, netif);
    }
}

//---------------------------------------------------------------------------
// External/Public API - Register all interfaces.

IOReturn
IONetworkStack::registerAllInterfaces()
{
    IONetworkInterface * netif;
    const UInt32         unit = 0;
    OSArray *            array;

    lockForArbitration();

    // Allocate array to hold pre-registered interface objects.

    array = OSArray::withCapacity( _ifSet->getCount() );
    if ( array == 0 )
    {
        unlockForArbitration();
        return kIOReturnNoMemory;
    }

    // Iterate through all interface objects.

    for ( UInt32 index = 0; ( netif = getInterface(index) ); index++ )
    {
        // Interface must be Active and not yet registered.

        if ( NETIF_FLAGS(netif) != kInterfaceFlagActive )
        {
            continue;
        }

        // Pre-register the interface.

        preRegisterInterface( netif,
                              netif->getNamePrefix(),
                              unit,
                              array );
    }

    unlockForArbitration();

    // Complete registration without holding the arbitration lock.

    completeRegistration( array, true );

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// External/Public API - Register primary interface.

IOReturn IONetworkStack::registerPrimaryInterface( bool enable )
{
    IONetworkInterface * netif;
    const UInt32         unit = 0;
    OSArray *            array;

    lockForArbitration();

    _registerPrimaryInterface = enable;

    if ( _registerPrimaryInterface == false )
    {
        unlockForArbitration();
        return kIOReturnSuccess;
    }

    // Allocate array to hold pre-registered interface objects.

    array = OSArray::withCapacity( _ifSet->getCount() );
    if ( array == 0 )
    {
        unlockForArbitration();
        return kIOReturnNoMemory;
    }

    // Iterate through all interface objects.

    for ( UInt32 index = 0; ( netif = getInterface(index) ); index++ )
    {
        const char * prefix = netif->getNamePrefix();
    
        // Interface must be Active and not yet registered.

        if ( NETIF_FLAGS(netif) != kInterfaceFlagActive )
        {
            continue;
        }

        // Primary only.

        if ( netif->isPrimaryInterface() != true )
        {
            continue;
        }

        // If the unit slot is already taken, forget it.

        if ( getRegisteredInterface( prefix, unit ) )
        {
            continue;
        }

        // Pre-register the interface.

        preRegisterInterface( netif, prefix, unit, array );
    }

    unlockForArbitration();

    // Complete registration without holding the arbitration lock.

    completeRegistration( array, true );

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// External/Public API - Register a single interface.

IOReturn IONetworkStack::registerInterface( IONetworkInterface * netif,
                                            const char *         prefix,
                                            UInt32               unit,
                                            bool                 isSync )
{
    bool       ret;
    OSArray *  array;

    // Create pre-registration array.

    array = OSArray::withCapacity( 1 );
    if ( array == 0 )
    {
        return kIOReturnNoMemory;
    }

    // Pre-registration has to be serialized, but the registration can
    // (and should) be completed without holding a lock. If the interface
    // has already been registered, or cannot be registered, then the
    // return value will be false.

    lockForArbitration();
    ret = preRegisterInterface( netif, prefix, unit, array );
    unlockForArbitration();

    // Complete the registration synchronously or asynchronously.
    // If synchronous, then this call will return after the interface
    // object in the array has registered with DLIL.

    completeRegistration( array, isSync );

    return ret ? kIOReturnSuccess : kIOReturnError;
}

//---------------------------------------------------------------------------
// Registered interfaces are ordered by their assigned unit number. Those with
// larger unit numbers will be placed behind those with smaller unit numbers.
// This ordering makes it easier to hunt for an available unit number slot for
// a new interface.

SInt32 IONetworkStack::
orderRegisteredInterfaces( const OSMetaClassBase * obj1,
                           const OSMetaClassBase * obj2,
                           void *     ref )
{
    const IONetworkInterface * netif1 = (const IONetworkInterface *) obj1;
    const IONetworkInterface * netif2 = (const IONetworkInterface *) obj2;

    assert( netif1 && netif2 );

    return ( netif2->getUnitNumber() - netif1->getUnitNumber() );
}

//---------------------------------------------------------------------------
// Create a user-client object to manage user space access.

IOReturn IONetworkStack::newUserClient( task_t           owningTask,
                                        void *           /* security_id */,
                                        UInt32           /* type */,
                                        IOUserClient **  handler )
{
    IOReturn       err = kIOReturnSuccess;
    IOUserClient * client;

    client = IONetworkStackUserClient::withTask(owningTask);

    if (!client || !client->attach(this) || !client->start(this))
    {
        if (client)
        {
            client->detach(this);
            client->release();
            client = 0;
            err = kIOReturnExclusiveAccess;
        }
        else
        {
            err = kIOReturnNoMemory;
        }
    }

    *handler = client;

    return err;
}

//---------------------------------------------------------------------------
// IONetworkStackUserClient implementation.

#undef  super
#define super IOUserClient
OSDefineMetaClassAndStructors( IONetworkStackUserClient, IOUserClient )

IONetworkStackUserClient * IONetworkStackUserClient::withTask( task_t task )
{
    IONetworkStackUserClient * me = new IONetworkStackUserClient;

    if ( me && me->init() == false )
    {
        me->release();
        return 0;
    }
    return me;
}

bool IONetworkStackUserClient::start( IOService * provider )
{
    if ( super::start(provider) == false )
        return false;

    if ( provider->open(this) == false )
        return false;

    _provider = (IONetworkStack *) provider;

    return true;
}

IOReturn IONetworkStackUserClient::clientClose()
{
    if (_provider)
    {
        _provider->close(this);
        detach(_provider);
    }
    return kIOReturnSuccess;
}

IOReturn IONetworkStackUserClient::clientDied()
{
    return clientClose();
}

IOReturn IONetworkStackUserClient::setProperties( OSObject * properties )
{
    IONetworkInterface * netif;
    OSDictionary *       dict = OSDynamicCast(OSDictionary, properties);
    IOReturn             ret  = kIOReturnBadArgument;
    OSString *           path = 0;
    OSNumber *           unit;
    OSNumber *           cmd;

    do {
        // Sanity check.

        if ( (_provider == 0) || (dict == 0) )
            break;

        // Switch on the specified user command.

        cmd = OSDynamicCast( OSNumber,
                             dict->getObject( kIONetworkStackUserCommand ) );
        if ( cmd == 0 )
            break;

        switch ( cmd->unsigned32BitValue() )
        {
        	// Register one interface.

            case kIORegisterOne:
            	path = OSDynamicCast( OSString,
            	                      dict->getObject( kIOPathMatchKey ));
                unit = OSDynamicCast( OSNumber,
                                      dict->getObject( kIOInterfaceUnit ));
                
                if ( (path == 0) || (unit == 0) )
            	{
                	break;
            	}
                
                netif = OSDynamicCast( IONetworkInterface,
                        IORegistryEntry::fromPath( path->getCStringNoCopy()) );
                        
                if ( netif == 0 ) break;

                ret = _provider->registerInterface( netif,
                                         netif->getNamePrefix(),
                                         unit->unsigned32BitValue() );

                netif->release();   // offset the retain by fromPath().

            	break;

            // Register all interfaces.

            case kIORegisterAll:
                ret = _provider->registerAllInterfaces();
                break;
        }
    }
    while ( false );

    return ret;
}
