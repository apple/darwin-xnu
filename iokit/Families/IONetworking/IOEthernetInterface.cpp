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
 * IOEthernetInterface.cpp
 *
 * HISTORY
 * 8-Jan-1999       Joe Liu (jliu) created.
 *
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IONetworkUserClient.h>

extern "C" {
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/etherdefs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/sockio.h>
#include <netinet/in_var.h>
#include <sys/malloc.h>
void arpwhohas(struct arpcom * ac, struct in_addr * addr);
}

//---------------------------------------------------------------------------

#define super IONetworkInterface

OSDefineMetaClassAndStructors( IOEthernetInterface, IONetworkInterface )
OSMetaClassDefineReservedUnused( IOEthernetInterface,  0);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  1);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  2);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  3);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  4);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  5);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  6);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  7);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  8);
OSMetaClassDefineReservedUnused( IOEthernetInterface,  9);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 10);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 11);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 12);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 13);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 14);
OSMetaClassDefineReservedUnused( IOEthernetInterface, 15);

// The name prefix for all BSD Ethernet interfaces.
// 
#define kIOEthernetInterfaceNamePrefix      "en"

//---------------------------------------------------------------------------
// Macros

#ifdef  DEBUG
#define DLOG(fmt, args...)  IOLog(fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

UInt32 IOEthernetInterface::getFilters(const OSDictionary * dict,
                                       const OSSymbol *     group)
{
    OSNumber * num;
    UInt32     filters = 0;

    assert( dict && group );

    if (( num = (OSNumber *) dict->getObject(group) ))
    {
        filters = num->unsigned32BitValue();
    }
    return filters;
}

bool IOEthernetInterface::setFilters(OSDictionary *   dict,
                                     const OSSymbol * group,
                                     UInt32           filters)
{
    OSNumber * num;
    bool       ret = false;

    assert( dict && group );

    num = (OSNumber *) dict->getObject(group);
    if ( num == 0 )
    {
        if (( num = OSNumber::withNumber(filters, 32) ))
        {
            ret = dict->setObject(group, num);
            num->release();
        }
    }
    else
    {
        num->setValue(filters);
        ret = true;
    }
    return ret;
}

#define GET_REQUIRED_FILTERS(g)     getFilters(_requiredFilters, (g))
#define GET_ACTIVE_FILTERS(g)       getFilters(_activeFilters, (g))
#define GET_SUPPORTED_FILTERS(g)    getFilters(_supportedFilters, (g))

#define SET_REQUIRED_FILTERS(g, v)  setFilters(_requiredFilters, (g), (v))
#define SET_ACTIVE_FILTERS(g, v)    setFilters(_activeFilters, (g), (v))

//---------------------------------------------------------------------------
// Initialize an IOEthernetInterface instance. Instance variables are
// initialized, and an arpcom structure is allocated.

bool IOEthernetInterface::init(IONetworkController * controller)
{
    // Allocate an arpcom structure, then call super::init().
    // We expect our superclass to call getIfnet() during its init()
    // method, so arpcom must be allocated before calling super::init().

    if ( (_arpcom = (struct arpcom *) IOMalloc(sizeof(*_arpcom))) == 0 )
    {
        DLOG("IOEthernetInterface: arpcom allocation failed\n");
        return false;
    }

    // Pass the init() call to our superclass.

    if ( super::init(controller) == false )
        return false;

    // Add an IONetworkData with room to hold an IOEthernetStats structure.
    // This class does not reference the data object created, and no harm
    // is done if the data object is released or replaced.

    IONetworkData * data = IONetworkData::withInternalBuffer(
                                              kIOEthernetStatsKey,
                                              sizeof(IOEthernetStats));
    if (data)
    {
        addNetworkData(data);
        data->release();
    }

    // Create and initialize the filter dictionaries.

    _requiredFilters = OSDictionary::withCapacity(4);
    _activeFilters   = OSDictionary::withCapacity(4);

    if ( (_requiredFilters == 0) || (_activeFilters == 0) )
        return false;

    _supportedFilters = OSDynamicCast(OSDictionary,
                        controller->getProperty(kIOPacketFilters));
    if ( _supportedFilters == 0 ) return false;
    _supportedFilters->retain();

    // Controller's Unicast (directed) and Broadcast filters should always
    // be enabled. Those bits should never be cleared.

    if ( !SET_REQUIRED_FILTERS( gIONetworkFilterGroup,
                                kIOPacketFilterUnicast |
                                kIOPacketFilterBroadcast )
      || !SET_REQUIRED_FILTERS( gIOEthernetWakeOnLANFilterGroup, 0 )
      || !SET_ACTIVE_FILTERS(   gIONetworkFilterGroup, 0 )
      || !SET_ACTIVE_FILTERS(   gIOEthernetWakeOnLANFilterGroup, 0 ) )
    {
         return false;
    }

    // Publish filter dictionaries to property table.

    setProperty( kIORequiredPacketFilters, _requiredFilters );
    setProperty( kIOActivePacketFilters,   _activeFilters );

    return true;
}

//---------------------------------------------------------------------------
// Initialize the given ifnet structure. The argument specified is a pointer
// to an ifnet structure obtained through getIfnet(). IOEthernetInterface
// will initialize this structure in a manner that is appropriate for most
// Ethernet interfaces, then call super::initIfnet() to allow the superclass
// to perform generic interface initialization.
//
// ifp: Pointer to the ifnet structure to be initialized.
//
// Returns true on success, false otherwise.

bool IOEthernetInterface::initIfnet(struct ifnet * ifp)
{
    struct arpcom * ac = (struct arpcom *) ifp;

    assert(ac);

    lock();

    bzero(ac, sizeof(*ac));

    // Set defaults suitable for Ethernet interfaces.

    setInterfaceType( IFT_ETHER );
    setMaxTransferUnit( ETHERMTU );
    setMediaAddressLength( NUM_EN_ADDR_BYTES );
    setMediaHeaderLength( ETHERHDRSIZE );
    setFlags( IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS );

    unlock();

    return super::initIfnet(ifp);
}

//---------------------------------------------------------------------------
// Free the IOEthernetInterface instance. The memory allocated
// for the arpcom structure is released.

void IOEthernetInterface::free()
{
    if ( _arpcom )
    {
        IOFree(_arpcom, sizeof(*_arpcom));
        _arpcom = 0;
    }

    if ( _requiredFilters )
    {
        _requiredFilters->release();
        _requiredFilters = 0;
    }

    if ( _activeFilters )
    {
        _activeFilters->release();
        _activeFilters = 0;
    }
    
    if ( _supportedFilters )
    {
        _supportedFilters->release();
        _supportedFilters = 0; 
    }

    super::free();
}

//---------------------------------------------------------------------------
// This method returns a pointer to an ifnet structure maintained
// by the family specific interface object. IOEthernetInterface
// allocates an arpcom structure in init(), and returns a pointer
// to that structure when this method is called.
//
// Returns a pointer to an ifnet structure.

struct ifnet * IOEthernetInterface::getIfnet() const
{
    return (&(_arpcom->ac_if));
}

//---------------------------------------------------------------------------
// The name of the interface advertised to the network layer
// is generated by concatenating the string returned by this method,
// and an unit number.
//
// Returns a pointer to a constant string "en". Thus Ethernet interfaces
// will be registered as en0, en1, etc.

const char * IOEthernetInterface::getNamePrefix() const
{
    return kIOEthernetInterfaceNamePrefix;
}

//---------------------------------------------------------------------------
// Prepare the 'Ethernet' controller after it has been opened. This is called
// by IONetworkInterface after a controller has accepted an open from this 
// interface. IOEthernetInterface uses this method to inspect the controller,
// and to cache certain controller properties, such as its hardware address.
// This method is called with the arbitration lock held.
//
// controller: The controller object that was opened.
//
// Returns true on success, false otherwise
// (which will cause the controller to be closed).

bool IOEthernetInterface::controllerDidOpen(IONetworkController * ctr)
{
    bool                 ret = false;
    OSData *             addrData;
    IOEthernetAddress *  addr;

    do {
        // Call the controllerDidOpen() in superclass first.

        if ( (ctr == 0) || (super::controllerDidOpen(ctr) == false) )
             break;

        // If the controller supports some form of multicast filtering,
        // then set the ifnet IFF_MULTICAST flag.

        if ( GET_SUPPORTED_FILTERS(gIONetworkFilterGroup) &
             (kIOPacketFilterMulticast | kIOPacketFilterMulticastAll) )
        {
            setFlags(IFF_MULTICAST);
        }

        // Get the controller's MAC/Ethernet address.

        addrData = OSDynamicCast(OSData, ctr->getProperty(kIOMACAddress));
        if ( (addrData == 0) || (addrData->getLength() != NUM_EN_ADDR_BYTES) )
        {
            DLOG("%s: kIOMACAddress property access error (len %d)\n",
                 getName(), addrData ? addrData->getLength() : 0);
            break;
        }

        addr = (IOEthernetAddress *) addrData->getBytesNoCopy();

#if 1   // Print the address
        IOLog("%s: Ethernet address %02x:%02x:%02x:%02x:%02x:%02x\n",
              ctr->getName(),
              addr->bytes[0],
              addr->bytes[1],
              addr->bytes[2],
              addr->bytes[3],
              addr->bytes[4],
              addr->bytes[5]);
#endif

        // Copy the hardware address we obtained from the controller
        // to the arpcom structure.

        bcopy(addr, _arpcom->ac_enaddr, NUM_EN_ADDR_BYTES);
        
        ret = true;
    }
    while (0);

    return ret;
}

//---------------------------------------------------------------------------
// When a close from our last client is received, the interface will
// close the controller. But before the controller is closed, this method
// will be called by our superclass to perform any final cleanup. This
// method is called with the arbitration lock held.
//
// IOEthernetInterface will ensure that the controller is disabled.
//
// controller: The currently opened controller object.

void IOEthernetInterface::controllerWillClose(IONetworkController * ctr)
{
    super::controllerWillClose(ctr);
}

//---------------------------------------------------------------------------
// Handle ioctl commands originated from the network layer.
// Commands not handled by this method are passed to our superclass.
//
// Argument convention is:
//
//    arg0 - (struct ifnet *)
//    arg1 - (void *)
//
// The commands handled by IOEthernetInterface are:
//
//    SIOCSIFADDR
//    SIOCSIFFLAGS
//    SIOCADDMULTI
//    SIOCDELMULTI
//
// Returns an error code defined in errno.h (BSD).

SInt32 IOEthernetInterface::performCommand( IONetworkController * ctr,
                                            UInt32                cmd,
                                            void *                arg0,
                                            void *                arg1 )
{
    SInt32  ret;

    assert( arg0 == _arpcom );

    if ( ctr == 0 ) return EINVAL;

    switch ( cmd )
    {
        case SIOCSIFFLAGS:
        case SIOCADDMULTI:
        case SIOCDELMULTI:
        case SIOCSIFADDR:
        
            ret = (int) ctr->executeCommand(
                             this,            /* client */
                             (IONetworkController::Action)
                                &IOEthernetInterface::performGatedCommand,
                             this,            /* target */
                             ctr,             /* param0 */
                             (void *) cmd,    /* param1 */
                             arg0,            /* param2 */
                             arg1 );          /* param3 */
            break;

        default:
            // Unknown command, let our superclass deal with it.
            ret = super::performCommand(ctr, cmd, arg0, arg1);
            break;
    }

    return ret;
}

//---------------------------------------------------------------------------
// Handle an ioctl command on the controller's workloop context.

int IOEthernetInterface::performGatedCommand(void * target,
                                             void * arg1_ctr,
                                             void * arg2_cmd,
                                             void * arg3_0,
                                             void * arg4_1)
{
    IOEthernetInterface * self = (IOEthernetInterface *) target;
    IONetworkController * ctr  = (IONetworkController *) arg1_ctr;
    SInt                  ret  = EOPNOTSUPP;

    // Refuse to perform controller I/O if the controller is in a
    // low-power state that makes it "unusable".

    if ( self->_controllerLostPower ) return EPWROFF;

    self->lock();

    switch ( (UInt32) arg2_cmd )
    {
        case SIOCSIFADDR:
            ret = self->syncSIOCSIFADDR(ctr);
            break;

        case SIOCSIFFLAGS:
            ret = self->syncSIOCSIFFLAGS(ctr);
            break;

        case SIOCADDMULTI:
            ret = self->syncSIOCADDMULTI(ctr);
            break;

        case SIOCDELMULTI:
            ret = self->syncSIOCDELMULTI(ctr);
            break;
    }

    self->unlock();

    return ret;
}

//---------------------------------------------------------------------------
// enableController() is reponsible for calling the controller's enable()
// method and restoring the state of the controller. We assume that
// controllers can completely reset its state upon receiving a disable()
// method call. And when it is brought back up, the interface should
// assist in restoring the previous state of the Ethernet controller.

IOReturn IOEthernetInterface::enableController(IONetworkController * ctr)
{
    IOReturn   ret     = kIOReturnSuccess;
    bool       enabled = false;
    UInt32     filters;

    assert(ctr);

    do {
        // Is controller already enabled? If so, exit and return success.

        if ( _ctrEnabled )
            break;

        // Send the controller an enable command.
   
        if ( (ret = ctr->enable((IOService *) this)) != kIOReturnSuccess )
            break;     // unable to enable the controller.

        enabled = true;

        // Disable all Wake-On-LAN filters.

        filters = GET_ACTIVE_FILTERS(gIOEthernetWakeOnLANFilterGroup);

        for (UInt i = 0; i < (sizeof(filters) * 8); i++)
        {
            if ((1 << i) & filters)
            {
                disableFilter(ctr, gIOEthernetWakeOnLANFilterGroup,
                              (1 << i));
            }
        }

        // Restore current filter selection.

        SET_ACTIVE_FILTERS(gIONetworkFilterGroup, 0);
        filters = GET_REQUIRED_FILTERS(gIONetworkFilterGroup);

        for (UInt i = 0; i < (sizeof(filters) * 8); i++)
        {
            if ((1 << i) & filters)
            {
                if ( (ret = enableFilter(ctr, gIONetworkFilterGroup,
                                         (1 << i)))
                    != kIOReturnSuccess )
                    break;
            }
        }
        if ( ret != kIOReturnSuccess )
            break;

        // Restore multicast filter settings.

        syncSIOCADDMULTI(ctr);

        _ctrEnabled = true;

    } while (false);

    // Disable the controller if a serious error has occurred after the
    // controller has been enabled.

    if ( enabled && (ret != kIOReturnSuccess) )
    {
        ctr->disable((IOService *) this);
    }

    return ret;
}

//---------------------------------------------------------------------------
// Handles SIOCSIFFLAGS ioctl command for Ethernet interfaces. The network
// stack has changed the if_flags field in ifnet. Our job is to go
// through if_flags and see what has changed, and act accordingly.
//
// The fact that if_flags contains both generic and Ethernet specific bits
// means that we cannot move some of the default flag processing to the
// superclass.

int IOEthernetInterface::syncSIOCSIFFLAGS(IONetworkController * ctr)
{
    UInt16    flags = getFlags();
    IOReturn  ret   = kIOReturnSuccess;

    if ( ( ((flags & IFF_UP) == 0) || _controllerLostPower ) &&
         ( flags & IFF_RUNNING ) )
    {
        // If interface is marked down and it is currently running,
        // then stop it.

        ctr->disable((IOService *) this);
        flags &= ~IFF_RUNNING;
        _ctrEnabled = false;
    }
    else if ( ( flags & IFF_UP )                &&
              ( _controllerLostPower == false ) &&
              ((flags & IFF_RUNNING) == 0) )
    {
        // If interface is marked up and it is currently stopped,
        // then start it.

        if ( (ret = enableController(ctr)) == kIOReturnSuccess )
            flags |= IFF_RUNNING;
    }

    if ( flags & IFF_RUNNING )
    {
        IOReturn rc;

        // We don't expect multiple flags to be changed for a given
        // SIOCSIFFLAGS call.

        // Promiscuous mode

        rc = (flags & IFF_PROMISC) ?
             enableFilter(ctr, gIONetworkFilterGroup,
                          kIOPacketFilterPromiscuous) :
             disableFilter(ctr, gIONetworkFilterGroup,
                           kIOPacketFilterPromiscuous);

        if (ret == kIOReturnSuccess) ret = rc;

        // Multicast-All mode

        rc = (flags & IFF_ALLMULTI) ?
             enableFilter(ctr, gIONetworkFilterGroup,
                          kIOPacketFilterMulticastAll) :
             disableFilter(ctr, gIONetworkFilterGroup,
                           kIOPacketFilterMulticastAll);

        if (ret == kIOReturnSuccess) ret = rc;
    }

    // Update the flags field to pick up any modifications. Also update the
    // property table to reflect any flag changes.

    setFlags(flags, ~flags);

    return errnoFromReturn(ret);
}

//---------------------------------------------------------------------------
// Handles SIOCSIFADDR ioctl.

SInt IOEthernetInterface::syncSIOCSIFADDR(IONetworkController * ctr)
{
    IOReturn ret = kIOReturnSuccess;

    // Interface is implicitly brought up by an SIOCSIFADDR ioctl.

    setFlags(IFF_UP);

    if ( (getFlags() & IFF_RUNNING) == 0 )
    {
        if ( (ret = enableController(ctr)) == kIOReturnSuccess )
            setFlags(IFF_RUNNING);
    }
               
    return errnoFromReturn(ret);
}

//---------------------------------------------------------------------------
// Handle SIOCADDMULTI ioctl command.

SInt IOEthernetInterface::syncSIOCADDMULTI(IONetworkController * ctr)
{
    IOReturn ret;

    // Make sure multicast filter is active.

    ret = enableFilter(ctr, gIONetworkFilterGroup, kIOPacketFilterMulticast);

    if ( ret == kIOReturnSuccess )
    {
        // Load multicast addresses only if the filter was activated.

        ret = setupMulticastFilter(ctr);

        // If the list is now empty, then deactivate the multicast filter.

        if ( _mcAddrCount == 0 )
        {
            IOReturn dret = disableFilter(ctr, gIONetworkFilterGroup,
                                          kIOPacketFilterMulticast);

            if (ret == kIOReturnSuccess) ret = dret;
        }
    }

    return errnoFromReturn(ret);
}

//---------------------------------------------------------------------------
// Handle SIOCDELMULTI ioctl command.

SInt IOEthernetInterface::syncSIOCDELMULTI(IONetworkController * ctr)
{
    return syncSIOCADDMULTI(ctr);
}

//---------------------------------------------------------------------------
// Enable a packet filter.

IOReturn
IOEthernetInterface::enableFilter(IONetworkController * ctr,
                                  const OSSymbol *      group,
                                  UInt32                filter,
                                  IOOptionBits          options = 0)
{
    IOReturn   ret;
    UInt32     reqFilters;
    UInt32     actFilters;

    // If the controller does not support the packet filter,
    // there's no need to proceed.

    if (( GET_SUPPORTED_FILTERS(group) & filter ) == 0)
        return kIOReturnUnsupported;

    do {
        // Add specified filter to the set of required filters.

        reqFilters = GET_REQUIRED_FILTERS(group) | filter;
        SET_REQUIRED_FILTERS(group, reqFilters);

        // Abort if no changes are needed.

        ret = kIOReturnSuccess;

        actFilters = GET_ACTIVE_FILTERS(group);

        if ( (( actFilters ^ reqFilters ) & filter) == 0 )
            break;

        // Send a command to the controller driver.

        ret = ctr->enablePacketFilter(group, filter, actFilters, options);

        if ( ret == kIOReturnSuccess )
        {
            SET_ACTIVE_FILTERS(group, actFilters | filter);
        }
    }
    while (false);

    return ret;
}

//---------------------------------------------------------------------------
// Disable a packet filter.

IOReturn
IOEthernetInterface::disableFilter(IONetworkController * ctr,
                                   const OSSymbol *      group,
                                   UInt32                filter,
                                   IOOptionBits          options = 0)
{
    IOReturn   ret;
    UInt32     reqFilters;
    UInt32     actFilters;

    do {
        // Remove specified filter from the set of required filters.

        reqFilters = GET_REQUIRED_FILTERS(group) & ~filter;
        SET_REQUIRED_FILTERS(group, reqFilters);

        // Abort if no changes are needed.

        ret = kIOReturnSuccess;

        actFilters = GET_ACTIVE_FILTERS(group);

        if ( (( actFilters ^ reqFilters ) & filter) == 0 )
            break;

        // Send a command to the controller driver.

        ret = ctr->disablePacketFilter(group, filter, actFilters, options);

        if ( ret == kIOReturnSuccess )
        {
            SET_ACTIVE_FILTERS(group, actFilters & ~filter);
        }
    }
    while (false);

    return ret;
}

//---------------------------------------------------------------------------
// Cache the list of multicast addresses and send a command to the
// controller to update the multicast list.

IOReturn
IOEthernetInterface::setupMulticastFilter(IONetworkController * ctr)
{
    void *               multiAddrs = 0;
    UInt                 mcount;
    OSData *             mcData = 0;
    struct ifnet *       ifp = (struct ifnet *) _arpcom;
    struct ifmultiaddr * ifma;
    IOReturn             ret = kIOReturnSuccess;
    bool                 ok;

    assert(ifp);

    // Update the multicast addresses count ivar.

    mcount = 0;
    for (ifma = ifp->if_multiaddrs.lh_first;
         ifma != NULL;
         ifma = ifma->ifma_link.le_next)
    {
        if ((ifma->ifma_addr->sa_family == AF_UNSPEC) ||
            (ifma->ifma_addr->sa_family == AF_LINK))
            mcount++;
    }
    _mcAddrCount = mcount;

    if ( mcount )
    {
        char * addrp;
            
        mcData = OSData::withCapacity(mcount * NUM_EN_ADDR_BYTES);
        if (!mcData)
        {
            DLOG("%s: no memory for multicast address list\n", getName());
            return kIOReturnNoMemory;
        }
        
        // Loop through the linked multicast structures and write the
        // address to the OSData.

        for (ifma = ifp->if_multiaddrs.lh_first;
             ifma != NULL;
             ifma = ifma->ifma_link.le_next)
        {
            if (ifma->ifma_addr->sa_family == AF_UNSPEC) 
                addrp = &ifma->ifma_addr->sa_data[0];
            else
                if (ifma->ifma_addr->sa_family == AF_LINK)
                addrp = LLADDR((struct sockaddr_dl *) ifma->ifma_addr);
                else
                continue;

            ok = mcData->appendBytes((const void *) addrp, NUM_EN_ADDR_BYTES);
            assert(ok);
        }

        multiAddrs = (void *) mcData->getBytesNoCopy();
        assert(multiAddrs);
    }

    // Issue a controller command to setup the multicast filter.

    ret = ((IOEthernetController *)ctr)->setMulticastList(
                                            (IOEthernetAddress *) multiAddrs,
                                            mcount);
    if (mcData)
    {
        if (ret == kIOReturnSuccess)
            setProperty(kIOMulticastAddressList, mcData);

        mcData->release();
    }
    else {
        removeProperty(kIOMulticastAddressList);
    }

    return ret;
}

//---------------------------------------------------------------------------
// Power management support.
//
// Handlers called, with the controller's gate closed, in response to a
// controller power state change.

IOReturn
IOEthernetInterface::controllerWillChangePowerState(
                               IONetworkController * ctr,
                               IOPMPowerFlags        flags,
                               UInt32                stateNumber,
                               IOService *           policyMaker )
{
	if ( ( (flags & IOPMDeviceUsable ) == 0) && 
         ( _controllerLostPower == false ) )
    {
        _controllerLostPower = true;

        // Enable Magic Packet if supported.

        if ( GET_SUPPORTED_FILTERS(gIOEthernetWakeOnLANFilterGroup) &
             kIOEthernetWakeOnMagicPacket )
        {
            enableFilter(ctr, gIOEthernetWakeOnLANFilterGroup,
                         kIOEthernetWakeOnMagicPacket);
        }

        // Set _controllerLostPower, then call the SIOCSIFFLAGS handler to
        // disable the controller, then mark the interface as Not Running.

        syncSIOCSIFFLAGS(ctr);
    }
    
    return super::controllerWillChangePowerState( ctr, flags,
                                                  stateNumber,
                                                  policyMaker );
}

IOReturn
IOEthernetInterface::controllerDidChangePowerState(
                               IONetworkController * ctr,
                               IOPMPowerFlags        flags,
                               UInt32                stateNumber,
                               IOService *           policyMaker )
{
    IOReturn ret = super::controllerDidChangePowerState( ctr, flags,
                                                         stateNumber,
                                                         policyMaker );

    if ( ( flags & IOPMDeviceUsable ) && ( _controllerLostPower == true ) )
    {
        _controllerLostPower = false;

        // Clear _controllerLostPower, then call the SIOCSIFFLAGS handler to
        // perhaps enable the controller, restore all Ethernet controller
        // state, then mark the interface as Running.

        syncSIOCSIFFLAGS(ctr);
    }

    return ret;
}
