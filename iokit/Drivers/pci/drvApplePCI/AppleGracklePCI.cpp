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

#include <libkern/c++/OSContainers.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <libkern/OSByteOrder.h>

#include "AppleGracklePCI.h"

#include <IOKit/assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOPCIBridge

OSDefineMetaClassAndStructors(AppleGracklePCI, IOPCIBridge)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleGracklePCI::start( IOService * provider )
{
    IOPCIPhysicalAddress 	ioAddrCell;
    IOPhysicalAddress		ioPhys;
    IOPhysicalAddress		ioPhysLen;
    OSArray *			array;
    IODeviceMemory::InitElement	rangeList[ 3 ];
    IORegistryEntry *		bridge;
    OSData *			busProp;
    IOPCIAddressSpace           grackleSpace;
    UInt32                      picr1;
		
    if( 0 == (lock = IOSimpleLockAlloc()))
	return( false );

    ioAddrCell.physHi.bits 	= 0;
    ioAddrCell.physHi.s.space 	= kIOPCIIOSpace;
    ioAddrCell.physMid 		= 0;
    ioAddrCell.physLo 		= 0;
    ioAddrCell.lengthHi 	= 0;
    ioAddrCell.lengthLo 	= 0x10000;

    bridge = provider;

    if( ! IODTResolveAddressCell( bridge, (UInt32 *) &ioAddrCell,
		&ioPhys, &ioPhysLen) ) {

	IOLog("%s: couldn't find my base\n", getName());
	return( false);
    }

    /* define more explicit ranges */

    rangeList[0].start	= ioPhys;
    rangeList[0].length = ioPhysLen;
    rangeList[1].start	= ioPhys + 0x00c00000;
    rangeList[1].length = 4;
    rangeList[2].start	= ioPhys + 0x00e00000;
    rangeList[2].length	= 4;

    array = IODeviceMemory::arrayFromList( rangeList, 3 );
    if( !array)
	return( false);

    provider->setDeviceMemory( array );
    array->release();
    ioMemory = (IODeviceMemory *) array->getObject( 0 );

    if( (configAddrMap = provider->mapDeviceMemoryWithIndex( 1 )))
        configAddr = (volatile UInt32 *) configAddrMap->getVirtualAddress();
    if( (configDataMap = provider->mapDeviceMemoryWithIndex( 2 )))
        configData = (volatile UInt8 *) configDataMap->getVirtualAddress();

    if( !configAddr || !configData)
	return( false);

    busProp = (OSData *) bridge->getProperty("bus-range");
    if( busProp)
	primaryBus = *((UInt32 *) busProp->getBytesNoCopy());

    // Check to see if there is a set loop snoop property.
    if( provider->getProperty("set-loop-snoop")) {
        // Turn on the Loop Snoop bit in PICR1.
        // See: MPC106 User's Manual p. 3-55.
        grackleSpace.bits = 0x80000000;
        picr1 = configRead32(grackleSpace, 0xA8);
        picr1 |= (1 << 4);
        configWrite32(grackleSpace, 0xA8, picr1);
    }

    // register iteself so we can find it:
    registerService();

    // Publish the AccessMPC106PerformanceRegister platform function.
    publishResource("AccessMPC106PerformanceRegister", this);

    return( super::start( provider));
}

bool AppleGracklePCI::configure( IOService * provider )
{
    bool ok;

    ok = addBridgeMemoryRange( 0x80000000, 0x7f000000, true );
    ok = addBridgeIORange( 0, 0x10000 );

    return( super::configure( provider ));
}

void AppleGracklePCI::free()
{
    if( configAddrMap)
	configAddrMap->release();
    if( configDataMap)
	configDataMap->release();
    if( lock)
	IOSimpleLockFree( lock);

    super::free();
}

IODeviceMemory * AppleGracklePCI::ioDeviceMemory( void )
{
    return( ioMemory);
}

UInt8 AppleGracklePCI::firstBusNum( void )
{
    return( primaryBus );
}

UInt8 AppleGracklePCI::lastBusNum( void )
{
    return( firstBusNum() );
}

IOPCIAddressSpace AppleGracklePCI::getBridgeSpace( void )
{
    IOPCIAddressSpace	space;

    space.bits = 0;
    space.s.deviceNum = kBridgeSelfDevice;

    return( space );
}

inline void AppleGracklePCI::setConfigSpace( IOPCIAddressSpace space,
					UInt8 offset )
{
    IOPCIAddressSpace	addrCycle;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset & 0xfc;

    OSWriteSwapInt32( configAddr, 0, addrCycle.bits);
    eieio();
    OSReadSwapInt32( configAddr, 0 );
    eieio();
}


UInt32 AppleGracklePCI::configRead32( IOPCIAddressSpace space,
					UInt8 offset )
{
    UInt32		data;
    IOInterruptState	ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    data = OSReadSwapInt32( configData, 0 );
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return( data );
}

void AppleGracklePCI::configWrite32( IOPCIAddressSpace space, 
					UInt8 offset, UInt32 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    OSWriteSwapInt32( configData, 0, data );
    eieio();
    /* read to sync */
    (void) OSReadSwapInt32( configData, 0 );
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

UInt16 AppleGracklePCI::configRead16( IOPCIAddressSpace space,
					UInt8 offset )
{
    UInt16		data;
    IOInterruptState	ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    offset = (offset & 2);

    data = OSReadSwapInt16( configData, offset );
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return( data );
}

void AppleGracklePCI::configWrite16( IOPCIAddressSpace space, 
					UInt8 offset, UInt16 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    offset = (offset & 2);

    OSWriteSwapInt16( configData, offset, data );
    eieio();
    /* read to sync */
    (void) OSReadSwapInt16( configData, offset );
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

UInt8 AppleGracklePCI::configRead8( IOPCIAddressSpace space,
					UInt8 offset )
{
    UInt8		data;
    IOInterruptState	ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    offset = (offset & 3);

    data = configData[ offset ];
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return( data );
}

void AppleGracklePCI::configWrite8( IOPCIAddressSpace space, 
					UInt8 offset, UInt8 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    setConfigSpace( space, offset );

    offset = (offset & 3);

    configData[ offset ] = data;
    eieio();
    /* read to sync */
    data = configData[ offset ];
    eieio();

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

IOReturn AppleGracklePCI::callPlatformFunction(const OSSymbol *functionName,
					       bool waitForFunction,
					       void *param1, void *param2,
					       void *param3, void *param4)
{
  if (functionName->isEqualTo("AccessMPC106PerformanceRegister")) {
    return accessMPC106PerformanceRegister((bool)param1, (long)param2,
                                           (unsigned long *)param3);
  }
  
  return super::callPlatformFunction(functionName, waitForFunction,
                                     param1, param2, param3, param4);
}


enum {
  kMCMonitorModeControl = 0,
  kMCCommand,
  kMCPerformanceMonitor0,
  kMCPerformanceMonitor1,
  kMCPerformanceMonitor2,
  kMCPerformanceMonitor3
};

IOReturn AppleGracklePCI::accessMPC106PerformanceRegister(bool write,
							  long regNumber,
							  unsigned long *data)
{
  IOPCIAddressSpace grackleSpace;
  unsigned long     offset;
  
  switch (regNumber) {
  case kMCMonitorModeControl  : offset = kMPC106MMCR0; break;
  case kMCCommand             : offset = kMPC106CMDR0; break;
  case kMCPerformanceMonitor0 : offset = kMPC106PMC0; break;
  case kMCPerformanceMonitor1 : offset = kMPC106PMC1; break;
  case kMCPerformanceMonitor2 : offset = kMPC106PMC2; break;
  case kMCPerformanceMonitor3 : offset = kMPC106PMC3; break;
  default                     : return kIOReturnBadArgument;
  }
  
  if (data == 0) return kIOReturnBadArgument;
  
  grackleSpace.bits = 0x80000000;
  
  if (write) {
    configWrite32(grackleSpace, offset, *data);
  } else {
    *data = configRead32(grackleSpace, offset);
  }
  
  return kIOReturnSuccess;
}
