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
 * HISTORY
 * 23 Nov 98 sdouglas created from objc version.
 */
 
#include <IOKit/system.h>

#include <IOKit/pci/IOPCIBridge.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/pci/IOAGPDevice.h>
#include <IOKit/IOPlatformExpert.h>

#include <IOKit/IOLib.h>
#include <IOKit/assert.h>

#include <libkern/c++/OSContainers.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndStructors(IOPCIDevice, IOService)
OSMetaClassDefineReservedUnused(IOPCIDevice,  0);
OSMetaClassDefineReservedUnused(IOPCIDevice,  1);
OSMetaClassDefineReservedUnused(IOPCIDevice,  2);
OSMetaClassDefineReservedUnused(IOPCIDevice,  3);
OSMetaClassDefineReservedUnused(IOPCIDevice,  4);
OSMetaClassDefineReservedUnused(IOPCIDevice,  5);
OSMetaClassDefineReservedUnused(IOPCIDevice,  6);
OSMetaClassDefineReservedUnused(IOPCIDevice,  7);
OSMetaClassDefineReservedUnused(IOPCIDevice,  8);
OSMetaClassDefineReservedUnused(IOPCIDevice,  9);
OSMetaClassDefineReservedUnused(IOPCIDevice, 10);
OSMetaClassDefineReservedUnused(IOPCIDevice, 11);
OSMetaClassDefineReservedUnused(IOPCIDevice, 12);
OSMetaClassDefineReservedUnused(IOPCIDevice, 13);
OSMetaClassDefineReservedUnused(IOPCIDevice, 14);
OSMetaClassDefineReservedUnused(IOPCIDevice, 15);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// stub driver has two power states, off and on

enum { kIOPCIDevicePowerStateCount = 2 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// attach
//
// We clamp power on.  The effect is
// to prevent system sleep.  If a driver is loaded which can
// power manage the device, it will become our child and we
// will remove the clamp.  This prevents the system
// from sleeping when there are non-power-managed
// PCI cards installed.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPCIDevice::attach( IOService * provider )
{
    static const IOPMPowerState powerStates[ kIOPCIDevicePowerStateCount ] = {
        { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        { 1, IOPMPowerOn, IOPMPowerOn, IOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 }
    };

    // initialize superclass variables
    PMinit();
    // register as controlling driver
    registerPowerDriver( this, (IOPMPowerState *) powerStates,
                         kIOPCIDevicePowerStateCount );
    // join the tree
    provider->joinPMtree( this);

    // clamp power on if this is a slot device
    slotNameProperty = provider->getProperty ("AAPL,slot-name");
    if (slotNameProperty != NULL)
      changePowerStateToPriv (1);

    return super::attach(provider);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// maxCapabilityForDomainState
//
// If the power domain is supplying power, the device
// can be on.  If there is no power it can only be off.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

unsigned long IOPCIDevice::maxCapabilityForDomainState(
                                        IOPMPowerFlags domainState )
{
   if( domainState & IOPMPowerOn )
       return( kIOPCIDevicePowerStateCount - 1);
   else
       return( 0);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// initialPowerStateForDomainState
//
// This is our first information about the power domain state.
// If power is on in the new state, the device is on.
// If domain power is off, the device is also off.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
unsigned long IOPCIDevice::initialPowerStateForDomainState(
                                         IOPMPowerFlags domainState )
{
   if( domainState & IOPMPowerOn)
       return( kIOPCIDevicePowerStateCount - 1);
   else
       return( 0);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// powerStateForDomainState
//
// The power domain may be changing state.
// If power is on in the new state, the device will be on.
// If domain power is off, the device will be off.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

unsigned long  IOPCIDevice::powerStateForDomainState(
                                        IOPMPowerFlags domainState )
{
   if( domainState & IOPMPowerOn)
       return( pm_vars->myCurrentState);
   else
       return( 0);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// setPowerState
//
// Saves and restores PCI config space if power is going down or up.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOPCIDevice::setPowerState( unsigned long powerState,
                                     IOService * whatDevice )
{
    parent->setDevicePowerState( this, powerState );

    return( IOPMAckImplied);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// addPowerChild
//
//
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOPCIDevice::addPowerChild ( IOService * theChild )
{
  IOReturn result = IOPMNoErr;

  result = super::addPowerChild (theChild);

  if ((slotNameProperty != NULL) && (result == IOPMNoErr))
    changePowerStateToPriv(0);

  return result;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// joinPMtree
//
// A policy-maker for our PCI device calls here when initializing,
// to be attached into the power management hierarchy.
// We  attach this driver as our child so we can save and restore its config
// space across power cycles.
//
// This overrides the default function of the IOService joinPMtree.
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOPCIDevice::joinPMtree( IOService * driver )
{
    // hook it into the tree
    pm_vars->thePlatform->PMRegisterDevice( this, driver);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPCIDevice::matchPropertyTable( OSDictionary * table, SInt32 * score )
{
  return( parent->matchNubWithPropertyTable( this, table, score ));
}

bool IOPCIDevice::compareName( OSString * name, OSString ** matched = 0 ) const
{
    return( parent->compareNubName( this, name, matched ));
}

IOReturn IOPCIDevice::getResources( void )
{
    return( parent->getNubResources( this ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

UInt32 IOPCIDevice::configRead32( IOPCIAddressSpace _space,
					UInt8 offset )
{
    return( parent->configRead32( _space, offset ));
}

void IOPCIDevice::configWrite32( IOPCIAddressSpace _space, 
					UInt8 offset, UInt32 data )
{
    parent->configWrite32( _space, offset, data );
}

UInt16 IOPCIDevice::configRead16( IOPCIAddressSpace _space, 
                                        UInt8 offset )
{
    return( parent->configRead16( _space, offset ));
}

void IOPCIDevice::configWrite16( IOPCIAddressSpace _space, 
                                        UInt8 offset, UInt16 data )
{
    parent->configWrite16( _space, offset, data );
}

UInt8 IOPCIDevice::configRead8( IOPCIAddressSpace _space, 
                                        UInt8 offset )
{
    return( parent->configRead8( _space, offset ));
}

void IOPCIDevice::configWrite8( IOPCIAddressSpace _space, 
                                        UInt8 offset, UInt8 data )
{
    parent->configWrite8( _space, offset, data );
}

UInt32 IOPCIDevice::configRead32( UInt8 offset )
{
    return( parent->configRead32( space, offset ));
}

void IOPCIDevice::configWrite32( UInt8 offset, UInt32 data )
{
    parent->configWrite32( space, offset, data );
}

UInt16 IOPCIDevice::configRead16( UInt8 offset )
{
    return( parent->configRead16( space, offset ));
}

void IOPCIDevice::configWrite16( UInt8 offset, UInt16 data )
{
    parent->configWrite16( space, offset, data );
}

UInt8 IOPCIDevice::configRead8( UInt8 offset )
{
    return( parent->configRead8( space, offset ));
}

void IOPCIDevice::configWrite8( UInt8 offset, UInt8 data )
{
    parent->configWrite8( space, offset, data );
}

IOReturn IOPCIDevice::saveDeviceState( IOOptionBits options = 0 )
{
    return( parent->saveDeviceState( this, options ) );
}

IOReturn IOPCIDevice::restoreDeviceState( IOOptionBits options = 0 )
{
    return( parent->restoreDeviceState( this, options ) );
}

UInt32 IOPCIDevice::findPCICapability( UInt8 capabilityID, UInt8 * offset = 0 )
{
    return( parent->findPCICapability( space, capabilityID, offset ));
}

UInt32 IOPCIDevice::setConfigBits( UInt8 reg, UInt32 mask, UInt32 value )
{
    UInt32	was;
    UInt32	bits;

    bits = configRead32( reg );
    was = (bits & mask);
    bits &= ~mask;
    bits |= (value & mask);
    configWrite32( reg, bits );

    return( was );
}

bool IOPCIDevice::setBusMasterEnable( bool enable )
{
    return( 0 != setConfigBits( kIOPCIConfigCommand, kIOPCICommandBusMaster,
				enable ? kIOPCICommandBusMaster : 0));
}

bool IOPCIDevice::setMemoryEnable( bool enable )
{
    return( 0 != setConfigBits( kIOPCIConfigCommand, kIOPCICommandMemorySpace,
				enable ? kIOPCICommandMemorySpace : 0));
}

bool IOPCIDevice::setIOEnable( bool enable, bool /* exclusive = false */ )
{
    // exclusive is TODO.
    return( 0 != setConfigBits( kIOPCIConfigCommand, kIOPCICommandIOSpace,
				enable ? kIOPCICommandIOSpace : 0));
}

UInt8 IOPCIDevice::getBusNumber( void )
{
    return( space.s.busNum );
}

UInt8 IOPCIDevice::getDeviceNumber( void )
{
    return( space.s.deviceNum );
}

UInt8 IOPCIDevice::getFunctionNumber( void )
{
    return( space.s.functionNum );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IODeviceMemory * IOPCIDevice::getDeviceMemoryWithRegister( UInt8 reg )
{
    OSArray *		array;
    IODeviceMemory *	range;
    unsigned int	i = 0;

    array = (OSArray *) getProperty( gIODeviceMemoryKey);
    if( 0 == array)
	return( 0);

    while( (range = (IODeviceMemory *) array->getObject( i++ ))) {
	if( reg == (range->getTag() & 0xff))
	    break;
    }

    return( range);
}

IOMemoryMap * IOPCIDevice:: mapDeviceMemoryWithRegister( UInt8 reg,
						IOOptionBits options = 0 )
{
    IODeviceMemory *	range;
    IOMemoryMap *	map;

    range = getDeviceMemoryWithRegister( reg );
    if( range)
	map = range->map( options );
    else
	map = 0;

    return( map );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IODeviceMemory * IOPCIDevice::ioDeviceMemory( void )
{
    return( parent->ioDeviceMemory() );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOService * IOPCIDevice::matchLocation( IOService * /* client */ )
{
      return( this );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOPCIDevice

OSDefineMetaClassAndStructors(IOAGPDevice, IOPCIDevice)
OSMetaClassDefineReservedUnused(IOAGPDevice,  0);
OSMetaClassDefineReservedUnused(IOAGPDevice,  1);
OSMetaClassDefineReservedUnused(IOAGPDevice,  2);
OSMetaClassDefineReservedUnused(IOAGPDevice,  3);
OSMetaClassDefineReservedUnused(IOAGPDevice,  4);
OSMetaClassDefineReservedUnused(IOAGPDevice,  5);
OSMetaClassDefineReservedUnused(IOAGPDevice,  6);
OSMetaClassDefineReservedUnused(IOAGPDevice,  7);
OSMetaClassDefineReservedUnused(IOAGPDevice,  8);
OSMetaClassDefineReservedUnused(IOAGPDevice,  9);
OSMetaClassDefineReservedUnused(IOAGPDevice, 10);
OSMetaClassDefineReservedUnused(IOAGPDevice, 11);
OSMetaClassDefineReservedUnused(IOAGPDevice, 12);
OSMetaClassDefineReservedUnused(IOAGPDevice, 13);
OSMetaClassDefineReservedUnused(IOAGPDevice, 14);
OSMetaClassDefineReservedUnused(IOAGPDevice, 15);
OSMetaClassDefineReservedUnused(IOAGPDevice, 16);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOAGPDevice::createAGPSpace( IOOptionBits options,
				IOPhysicalAddress * address, 
				IOPhysicalLength * length )
{
    return( parent->createAGPSpace( this, options, address, length ));
}

IOReturn IOAGPDevice::destroyAGPSpace( void )
{
    return( parent->destroyAGPSpace( this ));
}

IORangeAllocator * IOAGPDevice::getAGPRangeAllocator( void )
{
    return( parent->getAGPRangeAllocator( this ));
}

IOOptionBits IOAGPDevice::getAGPStatus( IOOptionBits options = 0 )
{
    return( parent->getAGPStatus( this, options ));
}

IOReturn IOAGPDevice::resetAGP( IOOptionBits options = 0 )
{
    return( parent->resetAGPDevice( this, options ));
}

IOReturn IOAGPDevice::getAGPSpace( IOPhysicalAddress * address, 
				    IOPhysicalLength * length )
{
    return( parent->getAGPSpace( this, address, length ));
}

IOReturn IOAGPDevice::commitAGPMemory(  IOMemoryDescriptor * memory,
					IOByteCount agpOffset,
					IOOptionBits options = 0 )
{
    return( parent->commitAGPMemory( this, memory, agpOffset, options ));
}

IOReturn IOAGPDevice::releaseAGPMemory( IOMemoryDescriptor * memory,
					IOByteCount agpOffset,
					IOOptionBits options = 0 )
{
    return( parent->releaseAGPMemory( this, memory, agpOffset, options ));
}


