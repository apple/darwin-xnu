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
 * IOEthernetController.cpp
 *
 * Abstract Ethernet controller superclass.
 *
 * HISTORY
 *
 * Dec 3, 1998  jliu - C++ conversion.
 */

#include <IOKit/assert.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>

extern "C" {
#include <sys/socket.h>
#include <net/if.h>
#include <net/etherdefs.h>
}

//---------------------------------------------------------------------------

#define super IONetworkController

OSDefineMetaClassAndAbstractStructors( IOEthernetController, IONetworkController)
OSMetaClassDefineReservedUnused( IOEthernetController,  0);
OSMetaClassDefineReservedUnused( IOEthernetController,  1);
OSMetaClassDefineReservedUnused( IOEthernetController,  2);
OSMetaClassDefineReservedUnused( IOEthernetController,  3);
OSMetaClassDefineReservedUnused( IOEthernetController,  4);
OSMetaClassDefineReservedUnused( IOEthernetController,  5);
OSMetaClassDefineReservedUnused( IOEthernetController,  6);
OSMetaClassDefineReservedUnused( IOEthernetController,  7);
OSMetaClassDefineReservedUnused( IOEthernetController,  8);
OSMetaClassDefineReservedUnused( IOEthernetController,  9);
OSMetaClassDefineReservedUnused( IOEthernetController, 10);
OSMetaClassDefineReservedUnused( IOEthernetController, 11);
OSMetaClassDefineReservedUnused( IOEthernetController, 12);
OSMetaClassDefineReservedUnused( IOEthernetController, 13);
OSMetaClassDefineReservedUnused( IOEthernetController, 14);
OSMetaClassDefineReservedUnused( IOEthernetController, 15);
OSMetaClassDefineReservedUnused( IOEthernetController, 16);
OSMetaClassDefineReservedUnused( IOEthernetController, 17);
OSMetaClassDefineReservedUnused( IOEthernetController, 18);
OSMetaClassDefineReservedUnused( IOEthernetController, 19);
OSMetaClassDefineReservedUnused( IOEthernetController, 20);
OSMetaClassDefineReservedUnused( IOEthernetController, 21);
OSMetaClassDefineReservedUnused( IOEthernetController, 22);
OSMetaClassDefineReservedUnused( IOEthernetController, 23);
OSMetaClassDefineReservedUnused( IOEthernetController, 24);
OSMetaClassDefineReservedUnused( IOEthernetController, 25);
OSMetaClassDefineReservedUnused( IOEthernetController, 26);
OSMetaClassDefineReservedUnused( IOEthernetController, 27);
OSMetaClassDefineReservedUnused( IOEthernetController, 28);
OSMetaClassDefineReservedUnused( IOEthernetController, 29);
OSMetaClassDefineReservedUnused( IOEthernetController, 30);
OSMetaClassDefineReservedUnused( IOEthernetController, 31);

//-------------------------------------------------------------------------
// Macros

#ifdef  DEBUG
#define DLOG(fmt, args...)  IOLog(fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

//---------------------------------------------------------------------------
// IOEthernetController class initializer.

void IOEthernetController::initialize()
{
}

//---------------------------------------------------------------------------
// Initialize an IOEthernetController instance.

bool IOEthernetController::init(OSDictionary * properties)
{
    if (!super::init(properties))
    {
        DLOG("IOEthernetController: super::init() failed\n");
        return false;
    }

    return true;
}

//---------------------------------------------------------------------------
// Free the IOEthernetController instance.

void IOEthernetController::free()
{
    // Any allocated resources should be released here.

    super::free();
}

//---------------------------------------------------------------------------
// Publish Ethernet controller capabilites and properties.

bool IOEthernetController::publishProperties()
{
    bool              ret = false;
    IOEthernetAddress addr;
    OSDictionary *    dict;

    do {
        // Let the superclass publish properties first.

        if (super::publishProperties() == false)
            break;

        // Publish the controller's Ethernet address.

        if ( (getHardwareAddress(&addr) != kIOReturnSuccess) ||
             (setProperty(kIOMACAddress,  (void *) &addr,
                          kIOEthernetAddressSize) == false) )
        {
            break;
        }

        // Publish Ethernet defined packet filters.
        
        dict = OSDynamicCast(OSDictionary, getProperty(kIOPacketFilters));
        if ( dict )
        {
            UInt32     filters;
            OSNumber * num;
            
            if ( getPacketFilters(gIOEthernetWakeOnLANFilterGroup,
                                  &filters) != kIOReturnSuccess )
            {
                break;
            }

            num = OSNumber::withNumber(filters, sizeof(filters) * 8);
            if (num == 0)
                break;

            ret = dict->setObject(gIOEthernetWakeOnLANFilterGroup, num);
            num->release();
        }
    }
    while (false);

    return ret;
}

//---------------------------------------------------------------------------
// Set or change the station address used by the Ethernet controller.

IOReturn
IOEthernetController::setHardwareAddress(const IOEthernetAddress * addr)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Enable or disable multicast mode.

IOReturn IOEthernetController::setMulticastMode(bool active)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Enable or disable promiscuous mode.

IOReturn IOEthernetController::setPromiscuousMode(bool active)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Enable or disable the wake on Magic Packet support.

IOReturn IOEthernetController::setWakeOnMagicPacket(bool active)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Set the list of multicast addresses that the multicast filter should use
// to match against the destination address of an incoming frame. The frame 
// should be accepted when a match occurs.

IOReturn IOEthernetController::setMulticastList(IOEthernetAddress * /*addrs*/,
                                                UInt32              /*count*/)
{
    return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Allocate and return a new IOEthernetInterface instance.

IONetworkInterface * IOEthernetController::createInterface()
{
    IOEthernetInterface * netif = new IOEthernetInterface;

    if ( netif && ( netif->init( this ) == false ) )
    {
        netif->release();
        netif = 0;
    }
    return netif;
}

//---------------------------------------------------------------------------
// Returns all the packet filters supported by the Ethernet controller.
// This method will perform a bitwise OR of:
//
//    kIOPacketFilterUnicast
//    kIOPacketFilterBroadcast
//    kIOPacketFilterMulticast
//    kIOPacketFilterPromiscuous
//
// and write it to the argument provided if the group specified is
// gIONetworkFilterGroup, otherwise 0 is returned. Drivers that support
// a different set of filters should override this method.
//
// Returns kIOReturnSuccess. Drivers that override this method must return
// kIOReturnSuccess to indicate success, or an error code otherwise.

IOReturn
IOEthernetController::getPacketFilters(const OSSymbol * group,
                                       UInt32 *         filters) const
{
    *filters = 0;

    if ( group == gIONetworkFilterGroup )
    {
        return getPacketFilters(filters);
    }
    else
    {
        return kIOReturnSuccess;
    }
}

IOReturn IOEthernetController::getPacketFilters(UInt32 * filters) const
{
    *filters = ( kIOPacketFilterUnicast     |
                 kIOPacketFilterBroadcast   |
                 kIOPacketFilterMulticast   |
                 kIOPacketFilterPromiscuous );

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Enable a filter from the specified group.

#define UCAST_BCAST_MASK \
        ( kIOPacketFilterUnicast | kIOPacketFilterBroadcast )

IOReturn IOEthernetController::enablePacketFilter(
                                     const OSSymbol * group,
                                     UInt32           aFilter,
                                     UInt32           enabledFilters,
                                     IOOptionBits     options = 0)
{
    IOReturn  ret = kIOReturnUnsupported;
    UInt32    newFilters = enabledFilters | aFilter;

    if ( group == gIONetworkFilterGroup )
    {
        // The default action is to call setMulticastMode() or
        // setPromiscuousMode() to handle multicast or promiscuous
        // filter changes.

        if ( aFilter == kIOPacketFilterMulticast )
        {
            ret = setMulticastMode(true);
        }
        else if ( aFilter == kIOPacketFilterPromiscuous )
        {
            ret = setPromiscuousMode(true);
        }
        else if ( (newFilters ^ enabledFilters) & UCAST_BCAST_MASK )
        {
            ret = kIOReturnSuccess;
        }
    }
    else if ( group == gIOEthernetWakeOnLANFilterGroup )
    {
        if ( aFilter == kIOEthernetWakeOnMagicPacket )
        {
            ret = setWakeOnMagicPacket(true);
        }
    }

    return ret;
}

//---------------------------------------------------------------------------
// Disable a filter from the specifed filter group.

IOReturn IOEthernetController::disablePacketFilter(
                                      const OSSymbol * group,
                                      UInt32           aFilter,
                                      UInt32           enabledFilters,
                                      IOOptionBits     options = 0)
{
    IOReturn  ret = kIOReturnUnsupported;
    UInt32    newFilters = enabledFilters & ~aFilter;
        
    if ( group == gIONetworkFilterGroup )
    {
        // The default action is to call setMulticastMode() or
        // setPromiscuousMode() to handle multicast or promiscuous
        // filter changes.
    
        if ( aFilter == kIOPacketFilterMulticast )
        {
            ret = setMulticastMode(false);
        }
        else if ( aFilter == kIOPacketFilterPromiscuous )
        {
            ret = setPromiscuousMode(false);
        }
        else if ( (newFilters ^ enabledFilters) & UCAST_BCAST_MASK )
        {
            ret = kIOReturnSuccess;
        }
    }
    else if ( group == gIOEthernetWakeOnLANFilterGroup )
    {
        if ( aFilter == kIOEthernetWakeOnMagicPacket )
        {
            ret = setWakeOnMagicPacket(false);
        }
    }

    return ret;
}

//---------------------------------------------------------------------------
// Get the Ethernet controller's station address.
// Call the Ethernet specific (overloaded) form.

IOReturn
IOEthernetController::getHardwareAddress(void *   addr,
                                         UInt32 * inOutAddrBytes)
{
    UInt32 bufBytes;

    if (inOutAddrBytes == 0)
        return kIOReturnBadArgument;

    // Cache the size of the caller's buffer, and replace it with the
    // number of bytes required.

    bufBytes        = *inOutAddrBytes;
    *inOutAddrBytes = kIOEthernetAddressSize;

    // Make sure the buffer is large enough for a single Ethernet
    // hardware address.

    if ((addr == 0) || (bufBytes < kIOEthernetAddressSize))
        return kIOReturnNoSpace;

    return getHardwareAddress((IOEthernetAddress *) addr);
}

//---------------------------------------------------------------------------
// Set or change the station address used by the Ethernet controller.
// Call the Ethernet specific (overloaded) version of this method.

IOReturn
IOEthernetController::setHardwareAddress(const void * addr,
                                         UInt32       addrBytes)
{
    if ((addr == 0) || (addrBytes != kIOEthernetAddressSize))
        return kIOReturnBadArgument;

    return setHardwareAddress((const IOEthernetAddress *) addr);
}

//---------------------------------------------------------------------------
// Report the max/min packet sizes, including the frame header and FCS bytes.

IOReturn IOEthernetController::getMaxPacketSize(UInt32 * maxSize) const
{
    *maxSize = kIOEthernetMaxPacketSize;
    return kIOReturnSuccess;
}

IOReturn IOEthernetController::getMinPacketSize(UInt32 * minSize) const
{
    *minSize = kIOEthernetMinPacketSize;
    return kIOReturnSuccess;
}
