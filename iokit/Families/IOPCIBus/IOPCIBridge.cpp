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
 * Copyright (c) 1998-2000 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 * 23 Nov 98 sdouglas created from objc version.
 *
 */
 
#include <IOKit/system.h>

#include <IOKit/pci/IOPCIBridge.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/pci/IOAGPDevice.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/IOCatalogue.h>

#include <libkern/c++/OSContainers.h>

extern "C" {
#include <machine/machine_routines.h>
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndAbstractStructors( IOPCIBridge, IOService )
OSMetaClassDefineReservedUnused(IOPCIBridge,  0);
OSMetaClassDefineReservedUnused(IOPCIBridge,  1);
OSMetaClassDefineReservedUnused(IOPCIBridge,  2);
OSMetaClassDefineReservedUnused(IOPCIBridge,  3);
OSMetaClassDefineReservedUnused(IOPCIBridge,  4);
OSMetaClassDefineReservedUnused(IOPCIBridge,  5);
OSMetaClassDefineReservedUnused(IOPCIBridge,  6);
OSMetaClassDefineReservedUnused(IOPCIBridge,  7);
OSMetaClassDefineReservedUnused(IOPCIBridge,  8);
OSMetaClassDefineReservedUnused(IOPCIBridge,  9);
OSMetaClassDefineReservedUnused(IOPCIBridge, 10);
OSMetaClassDefineReservedUnused(IOPCIBridge, 11);
OSMetaClassDefineReservedUnused(IOPCIBridge, 12);
OSMetaClassDefineReservedUnused(IOPCIBridge, 13);
OSMetaClassDefineReservedUnused(IOPCIBridge, 14);
OSMetaClassDefineReservedUnused(IOPCIBridge, 15);
OSMetaClassDefineReservedUnused(IOPCIBridge, 16);
OSMetaClassDefineReservedUnused(IOPCIBridge, 17);
OSMetaClassDefineReservedUnused(IOPCIBridge, 18);
OSMetaClassDefineReservedUnused(IOPCIBridge, 19);
OSMetaClassDefineReservedUnused(IOPCIBridge, 20);
OSMetaClassDefineReservedUnused(IOPCIBridge, 21);
OSMetaClassDefineReservedUnused(IOPCIBridge, 22);
OSMetaClassDefineReservedUnused(IOPCIBridge, 23);
OSMetaClassDefineReservedUnused(IOPCIBridge, 24);
OSMetaClassDefineReservedUnused(IOPCIBridge, 25);
OSMetaClassDefineReservedUnused(IOPCIBridge, 26);
OSMetaClassDefineReservedUnused(IOPCIBridge, 27);
OSMetaClassDefineReservedUnused(IOPCIBridge, 28);
OSMetaClassDefineReservedUnused(IOPCIBridge, 29);
OSMetaClassDefineReservedUnused(IOPCIBridge, 30);
OSMetaClassDefineReservedUnused(IOPCIBridge, 31);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// 1 log, 2 disable DT
int gIOPCIDebug = 0;

#ifdef __I386__
static void setupIntelPIC(IOPCIDevice * nub);
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// stub driver has two power states, off and on

enum { kIOPCIBridgePowerStateCount = 2 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPCIBridge::start( IOService * provider )
{
    static const IOPMPowerState powerStates[ kIOPCIBridgePowerStateCount ] = {
        { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        { 1, IOPMPowerOn, IOPMPowerOn, IOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0 }
    };

    if( !super::start( provider))
	return( false);

    // empty ranges to start
    bridgeMemoryRanges = IORangeAllocator::withRange( 0, 1, 8,
						IORangeAllocator::kLocking );
    assert( bridgeMemoryRanges );
    setProperty( "Bridge Memory Ranges", bridgeMemoryRanges );

    bridgeIORanges = IORangeAllocator::withRange( 0, 1, 8,
						IORangeAllocator::kLocking );
    assert( bridgeIORanges );
    setProperty( "Bridge IO Ranges", bridgeIORanges );

    if( !configure( provider))
	return( false);

    // initialize superclass variables
    PMinit();
    // register as controlling driver
    registerPowerDriver( this, (IOPMPowerState *) powerStates,
                         kIOPCIBridgePowerStateCount);
    // join the tree
    provider->joinPMtree( this);
    // clamp power on
    temporaryPowerClampOn();

    probeBus( provider, firstBusNum() );

    return( true );
}

IOReturn IOPCIBridge::setDevicePowerState( IOPCIDevice * device,
                                            unsigned long powerState )
{
    if( powerState)
        return( restoreDeviceState( device));
    else
        return( saveDeviceState( device));
}

enum { kSavedConfigSize = 64 };
enum { kSavedConfigs = 16 };

IOReturn IOPCIBridge::saveDeviceState( IOPCIDevice * device,
                                       IOOptionBits options = 0 )
{
    int		i;

    if( !device->savedConfig)
        device->savedConfig = IONew( UInt32, kSavedConfigSize );
    if( !device->savedConfig)
        return( kIOReturnNotReady );

    for( i = 1; i < kSavedConfigs; i++)
        device->savedConfig[i] = device->configRead32( i * 4 );

    return( kIOReturnSuccess );
}

IOReturn IOPCIBridge::restoreDeviceState( IOPCIDevice * device,
                                          IOOptionBits options = 0 )
{
    int		i;

    if( !device->savedConfig)
        return( kIOReturnNotReady );

    for( i = 2; i < kSavedConfigs; i++)
        device->configWrite32( i * 4, device->savedConfig[ i ]);

    device->configWrite32( kIOPCIConfigCommand, device->savedConfig[1]);

    IODelete( device->savedConfig, UInt32, kSavedConfigSize);
    device->savedConfig = 0;

    return( kIOReturnSuccess );
}


bool IOPCIBridge::configure( IOService * provider )
{
    return( true );
}

static SInt32 PCICompare( UInt32 /* cellCount */, UInt32 cleft[], UInt32 cright[] )
{
    IOPCIPhysicalAddress *  left 	= (IOPCIPhysicalAddress *) cleft;
    IOPCIPhysicalAddress *  right 	= (IOPCIPhysicalAddress *) cright;
    static const UInt8      spacesEq[] 	= { 0, 1, 2, 2 };

    if( spacesEq[ left->physHi.s.space ] != spacesEq[ right->physHi.s.space ])
	return( -1);

    return( left->physLo - right->physLo );
}

void IOPCIBridge::nvLocation( IORegistryEntry * entry,
	UInt8 * busNum, UInt8 * deviceNum, UInt8 * functionNum )
{
    IOPCIDevice *	nub;

    nub = OSDynamicCast( IOPCIDevice, entry );
    assert( nub );

    *busNum		= nub->space.s.busNum;
    *deviceNum		= nub->space.s.deviceNum;
    *functionNum	= nub->space.s.functionNum;
}

void IOPCIBridge::spaceFromProperties( OSDictionary * propTable,
					IOPCIAddressSpace * space )
{
    OSData *			regProp;
    IOPCIAddressSpace * 	inSpace;

    space->bits = 0;

    if( (regProp = (OSData *) propTable->getObject("reg"))) {

	inSpace = (IOPCIAddressSpace *) regProp->getBytesNoCopy();
	space->s.busNum = inSpace->s.busNum;
	space->s.deviceNum = inSpace->s.deviceNum;
	space->s.functionNum = inSpace->s.functionNum;
    }
}

IORegistryEntry * IOPCIBridge::findMatching( OSIterator * kids,
					IOPCIAddressSpace space )
{
    IORegistryEntry *		found = 0;
    IOPCIAddressSpace		regSpace;

    if( kids) {
	kids->reset();
	while( (0 == found)
	    && (found = (IORegistryEntry *) kids->getNextObject())) {

            spaceFromProperties( found->getPropertyTable(), &regSpace);
            if( space.bits != regSpace.bits)
                found = 0;
        }
    }
    return( found );
}

OSDictionary * IOPCIBridge::constructProperties( IOPCIAddressSpace space )
{
    OSDictionary *	propTable;
    UInt32		value;
    UInt8		byte;
    UInt16		vendor, device;
    OSData *		prop;
    const char *	name;
    const OSSymbol *	nameProp;
    char *		nameStr;
    char *		compatBuf;
    char *		nextCompat;

    struct IOPCIGenericNames {
	const char *	name;
	UInt32		mask;
	UInt32		classCode;
    };
    static const IOPCIGenericNames genericNames[] = {
	{ "display", 	0xffffff, 0x000100 },
	{ "scsi", 	0xffff00, 0x010000 },
	{ "ethernet", 	0xffff00, 0x020000 },
	{ "display", 	0xff0000, 0x030000 },
	{ "pci-bridge", 0xffff00, 0x060400 },
	{ 0, 0, 0 }
    };
    const IOPCIGenericNames *	nextName;

    compatBuf = (char *) IOMalloc( 256 );

    propTable = OSDictionary::withCapacity( 8 );

    if( compatBuf && propTable) {

        prop = OSData::withBytes( &space, sizeof( space) );
        if( prop) {
            propTable->setObject("reg", prop );
            prop->release();
        }

        value = configRead32( space, kIOPCIConfigVendorID );
        vendor = value;
        device = value >> 16;

        prop = OSData::withBytes( &vendor, 2 );
        if( prop) {
            propTable->setObject("vendor-id", prop );
            prop->release();
        }
        
        prop = OSData::withBytes( &device, 2 );
        if( prop) {
            propTable->setObject("device-id", prop );
            prop->release();
        }

        value = configRead32( space, kIOPCIConfigRevisionID );
	byte = value & 0xff;
        prop = OSData::withBytes( &byte, 1 );
        if( prop) {
            propTable->setObject("revision-id", prop );
            prop->release();
        }

	// make generic name
	value >>= 8;
	name = 0;
	for( nextName = genericNames;
		(0 == name) && nextName->name;
		nextName++ ) {
	    if( (value & nextName->mask) == nextName->classCode)
		name = nextName->name;
	}

	// start compatible list
	nextCompat = compatBuf;
        sprintf( nextCompat, "pci%x,%x", vendor, device);
	nameStr = nextCompat;

        value = configRead32( space, kIOPCIConfigSubSystemVendorID );
        if( value) {
            vendor = value;
            device = value >> 16;

            prop = OSData::withBytes( &vendor, 2 );
            if( prop) {
                propTable->setObject("subsystem-vendor-id", prop );
                prop->release();
            }
            prop = OSData::withBytes( &device, 2 );
            if( prop) {
                propTable->setObject("subsystem-id", prop );
                prop->release();
            }

            nextCompat += strlen( nextCompat ) + 1;
            sprintf( nextCompat, "pci%x,%x", vendor, device);
	    nameStr = nextCompat;
        }

        nextCompat += strlen( nextCompat ) + 1;
        prop = OSData::withBytes( compatBuf, nextCompat - compatBuf);
        if( prop) {
            propTable->setObject( "compatible", prop );
            prop->release();
        }

	if( 0 == name)
            name = nameStr;

        nameProp = OSSymbol::withCString( name );
        if( nameProp) {
            propTable->setObject( gIONameKey, (OSSymbol *) nameProp);
            nameProp->release();
        }
    }

    if( compatBuf)
        IOFree( compatBuf, 256 );

    return( propTable );
}

IOPCIDevice * IOPCIBridge::createNub( OSDictionary * from )
{
    return( new IOPCIDevice );
}

bool IOPCIBridge::initializeNub( IOPCIDevice * nub,
      				  OSDictionary * from )
{
    spaceFromProperties( from, &nub->space);
    nub->parent = this;
    if( ioDeviceMemory())
        nub->ioMap = ioDeviceMemory()->map();

    return( true );
}

bool IOPCIBridge::publishNub( IOPCIDevice * nub, UInt32 /* index */ )
{
    char			location[ 24 ];
    bool			ok;
    OSData *			data;
    OSData *			driverData;
    UInt32			*regData, expRomReg;
    IOMemoryMap *		memoryMap;
    IOVirtualAddress		virtAddr;

    if( nub) {
	if( nub->space.s.functionNum)
	    sprintf( location, "%X,%X", nub->space.s.deviceNum,
                                        nub->space.s.functionNum );
	else
	    sprintf( location, "%X", nub->space.s.deviceNum );
        nub->setLocation( location );
	IODTFindSlotName( nub, nub->space.s.deviceNum );

	// Look for a "driver-reg,AAPL,MacOSX,PowerPC" property.
	if( (data = (OSData *)nub->getProperty( "driver-reg,AAPL,MacOSX,PowerPC"))) {
	  if( data->getLength() == (2 * sizeof(UInt32))) {
	    regData = (UInt32 *)data->getBytesNoCopy();

	    getNubResources(nub);
	    memoryMap = nub->mapDeviceMemoryWithRegister(kIOPCIConfigExpansionROMBase);
	    if( memoryMap != 0) {
	      virtAddr = memoryMap->getVirtualAddress();
	      virtAddr += regData[0];

	      nub->setMemoryEnable(true);

	      expRomReg = nub->configRead32(kIOPCIConfigExpansionROMBase);
	      nub->configWrite32(kIOPCIConfigExpansionROMBase, expRomReg | 1);

	      driverData = OSData::withBytesNoCopy((void *)virtAddr, regData[1]);
	      if ( driverData != 0) {
		gIOCatalogue->addExtensionsFromArchive(driverData);

		driverData->release();
	      }

	      nub->configWrite32(kIOPCIConfigExpansionROMBase, expRomReg);

	      nub->setMemoryEnable(false);

	      memoryMap->release();
	    }
	  }
	}

        ok = nub->attach( this );
        if( ok)
            nub->registerService();
    } else
	ok = false;

    return( ok );
}

void IOPCIBridge::publishNubs( OSIterator * kids, UInt32 index )
{
    IORegistryEntry *	found;
    IOPCIDevice *	nub;
    OSDictionary *	propTable;

    if( kids) {
        kids->reset();
	while( (found = (IORegistryEntry *) kids->getNextObject())) {

	    propTable = found->getPropertyTable();
            nub = createNub( propTable );
            if( !nub)
                continue;
	    if( !initializeNub( nub, propTable))
                continue;
	    if( !nub->init( found, gIODTPlane))
                continue;

	    publishNub( nub, index++ );

if( 1 & gIOPCIDebug)
	IOLog("%08lx = 0:%08lx 4:%08lx  ", nub->space.bits,
                    	nub->configRead32(kIOPCIConfigVendorID),
			nub->configRead32(kIOPCIConfigCommand) );

        }
    }
}

UInt8 IOPCIBridge::firstBusNum( void )
{
    return( 0 );
}

UInt8 IOPCIBridge::lastBusNum( void )
{
    return( 255 );
}

void IOPCIBridge::probeBus( IOService * provider, UInt8 busNum )
{
    IORegistryEntry *	regEntry;
    OSDictionary *	propTable;
    IOPCIDevice *	nub = 0;
    IOPCIAddressSpace	space;
    UInt32		vendor;
    UInt8		scanDevice, scanFunction, lastFunction;
    OSIterator *	kidsIter;
    UInt32		index = 0;

    IODTSetResolving( provider, PCICompare, nvLocation );

    if( 2 & gIOPCIDebug)
	kidsIter = 0;
    else
    kidsIter = provider->getChildIterator( gIODTPlane );

    space.bits = 0;
    space.s.busNum = busNum;

    for( scanDevice = 0; scanDevice <= 31; scanDevice++ ) {

        lastFunction = 0;
        for( scanFunction = 0; scanFunction <= lastFunction; scanFunction++ ) {

            space.s.deviceNum = scanDevice;
            space.s.functionNum = scanFunction;

            if( (regEntry = findMatching( kidsIter, space ))) {


	    } else {
		/* probe - should guard exceptions */
#ifdef __ppc__
		// DEC bridge really needs safe probe
		continue;
#endif
                vendor = configRead32( space, kIOPCIConfigVendorID );
                vendor &= 0x0000ffff;
                if( (0 == vendor) || (0xffff == vendor))
                    continue;

                // look in function 0 for multi function flag
                if( (0 == scanFunction)
		 && (0x00800000 & configRead32( space,
					kIOPCIConfigCacheLineSize )))
                    lastFunction = 7;

		propTable = constructProperties( space );
                if( propTable
		 && (nub = createNub( propTable))
		 && (initializeNub( nub, propTable))
		 && nub->init( propTable )) {
#ifdef __I386__
		    setupIntelPIC(nub);
#endif
                    publishNub( nub, index++);
		}
	    }
        }
    }

    if( kidsIter) {
        publishNubs( kidsIter, index );
        kidsIter->release();
    }
}

bool IOPCIBridge::addBridgeMemoryRange( IOPhysicalAddress start,
				  IOPhysicalLength length, bool host )
{
    IORangeAllocator *	platformRanges;
    bool		ok = true;

    if( host ) {

	platformRanges = getPlatform()->getPhysicalRangeAllocator();
	assert( platformRanges );

	// out of the platform
	ok = platformRanges->allocateRange( start, length );
	if( !ok)
	    kprintf("%s: didn't get host range (%08lx:%08lx)\n", getName(),
						start, length);
    }

    // and into the bridge
    bridgeMemoryRanges->deallocate( start, length );

    return( ok );
}

bool IOPCIBridge::addBridgeIORange( IOByteCount start, IOByteCount length )
{
    bool	ok = true;

    // into the bridge
    bridgeIORanges->deallocate( start, length );

    return( ok );
}

bool IOPCIBridge::constructRange( IOPCIAddressSpace * flags,
                                    IOPhysicalAddress phys,
				    IOPhysicalLength len,
                                    OSArray * array )
{
    IODeviceMemory *	range;
    IODeviceMemory *	ioMemory;
    IORangeAllocator *	bridgeRanges;
    bool		ok;

    if( !array)
	return( false );

    if( kIOPCIIOSpace == flags->s.space) {

	bridgeRanges = bridgeIORanges;
        if( (ioMemory = ioDeviceMemory())) {
	
	    phys &= 0x00ffffff;	// seems bogus
            range = IODeviceMemory::withSubRange( ioMemory, phys, len );
	    if( range == 0)
                /* didn't fit */
                range = IODeviceMemory::withRange(
				phys + ioMemory->getPhysicalAddress(), len );

	} else
	    range = 0;

    } else {
	bridgeRanges = bridgeMemoryRanges;
        range = IODeviceMemory::withRange( phys, len );
    }


    if( range) {

#ifdef i386
	// Do nothing for Intel -- I/O ports are not accessed through
	// memory on this platform, but through I/O port instructions
#else

	ok = bridgeRanges->allocateRange( phys, len );
	if( !ok)
	    IOLog("%s: bad range %d(%08lx:%08lx)\n", getName(), flags->s.space, 
						phys, len);
#endif

        range->setTag( flags->bits );
        ok = array->setObject( range );
        range->release();
	
    } else
	ok = false;

    return( ok );
}


IOReturn IOPCIBridge::getDTNubAddressing( IOPCIDevice * regEntry )
{
    OSArray *		array;
    IORegistryEntry *	parentEntry;
    OSData *		addressProperty;
    IOPhysicalAddress	phys;
    IOPhysicalLength	len;
    UInt32		cells = 5;
    int			i, num;
    UInt32 *		reg;

    addressProperty = (OSData *) regEntry->getProperty( "assigned-addresses" );
    if( 0 == addressProperty)
	return( kIOReturnSuccess );

    parentEntry = regEntry->getParentEntry( gIODTPlane );
    if( 0 == parentEntry)
	return( kIOReturnBadArgument );

    array = OSArray::withCapacity( 1 );
    if( 0 == array)
	return( kIOReturnNoMemory );

    reg = (UInt32 *) addressProperty->getBytesNoCopy();
    num = addressProperty->getLength() / (4 * cells);

    for( i = 0; i < num; i++) {

	if( IODTResolveAddressCell( parentEntry, reg, &phys, &len ))

	    constructRange( (IOPCIAddressSpace *) reg, phys, len, array );

        reg += cells;
    }

    if( array->getCount())
        regEntry->setProperty( gIODeviceMemoryKey, array);

    array->release();

    return( kIOReturnSuccess);
}

IOReturn IOPCIBridge::getNubAddressing( IOPCIDevice * nub )
{
    OSArray *		array;
    IOPhysicalAddress	phys;
    IOPhysicalLength	len;
    UInt32		save, value;
    IOPCIAddressSpace	reg;
    UInt8		regNum;
    bool		memEna, ioEna;
    boolean_t		s;

    value = nub->configRead32( kIOPCIConfigVendorID );
    if( 0x0003106b == value )		// control doesn't play well
	return( kIOReturnSuccess );

    // only header type 0
    value = nub->configRead32( kIOPCIConfigCacheLineSize );
    if( value & 0x007f0000)
	return( kIOReturnSuccess );

    array = OSArray::withCapacity( 1 );
    if( 0 == array)
	return( kIOReturnNoMemory );

    for( regNum = 0x10; regNum < 0x28; regNum += 4) {

	// begin scary
	s = ml_set_interrupts_enabled(FALSE);
	memEna = nub->setMemoryEnable( false );
	ioEna = nub->setIOEnable( false );

	save = nub->configRead32( regNum );

	nub->configWrite32( regNum, 0xffffffff );
	value = nub->configRead32( regNum );

	nub->configWrite32( regNum, save );
	nub->setMemoryEnable( memEna );
	nub->setIOEnable( ioEna );
	ml_set_interrupts_enabled( s );
	// end scary

	if( 0 == value)
	    continue;

        reg = nub->space;
	reg.s.registerNum = regNum;

	if( value & 1) {
	    reg.s.space = kIOPCIIOSpace;

	} else {
	    reg.s.prefetch = (0 != (value & 8));

	    switch( value & 6) {
		case 2: /* below 1Mb */
		    reg.s.t = 1;
		    /* fall thru */
		case 0: /* 32-bit mem */
		case 6:	/* reserved */
                    reg.s.space = kIOPCI32BitMemorySpace;
		    break;

		case 4: /* 64-bit mem */
                    reg.s.space = kIOPCI64BitMemorySpace;
		    regNum += 4;
		    break;
	     }
	}

        value &= 0xfffffff0;
        phys = IOPhysical32( 0, save & value );
        len = IOPhysical32( 0, -value );

if( 1 & gIOPCIDebug)
	IOLog("Space %08lx : %08lx, %08lx\n", reg.bits, phys, len);
	
        constructRange( &reg, phys, len, array );
    }

    if( array->getCount())
        nub->setProperty( gIODeviceMemoryKey, array);

    array->release();

    return( kIOReturnSuccess);
}

bool IOPCIBridge::isDTNub( IOPCIDevice * nub )
{
    return( 0 != nub->getParentEntry( gIODTPlane ));
}

IOReturn IOPCIBridge::getNubResources( IOService * service )
{
    IOPCIDevice *	nub = (IOPCIDevice *) service;
    IOReturn		err;

    if( service->getDeviceMemory())
	return( kIOReturnSuccess );

    if( isDTNub( nub))
        err = getDTNubAddressing( nub );
    else
	err = getNubAddressing( nub );

    return( err);
}

bool IOPCIBridge::matchKeys( IOPCIDevice * nub, const char * keys,
				UInt32 defaultMask, UInt8 regNum )
{
    const char *	next;
    UInt32		mask, value, reg;
    bool		found = false;

    do {
	value = strtoul( keys, (char **) &next, 16);
	if( next == keys)
	    break;

	while( (*next) == ' ')
	    next++;

	if( (*next) == '&')
	    mask = strtoul( next + 1, (char **) &next, 16);
	else
	    mask = defaultMask;

	reg = nub->configRead32( regNum );
	found = ((value & mask) == (reg & mask));
	keys = next;

    } while( !found);

    return( found );
}


bool IOPCIBridge::pciMatchNub( IOPCIDevice * nub,
                                    OSDictionary * table,
                                    SInt32 * score )
{
    OSString *		prop;
    const char *	keys;
    bool		match = true;
    UInt8		regNum;
    int			i;

    struct IOPCIMatchingKeys {
	const char *	propName;
	UInt8		regs[ 4 ];
	UInt32		defaultMask;
    };
    IOPCIMatchingKeys *		look;
    static IOPCIMatchingKeys	matching[] = {
	{ kIOPCIMatchKey,
		{ 0x00 + 1, 0x2c }, 0xffffffff },
	{ kIOPCIPrimaryMatchKey,
		{ 0x00 }, 0xffffffff },
	{ kIOPCISecondaryMatchKey,
		{ 0x2c }, 0xffffffff },
	{ kIOPCIClassMatchKey,
		{ 0x08 }, 0xffffff00 }};

    for( look = matching;
	 (match && (look < (&matching[4])));
	 look++ ) {

        prop = (OSString *) table->getObject( look->propName );
        if( prop) {
            keys = prop->getCStringNoCopy();
	    match = false;
	    for( i = 0;
		 ((false == match) && (i < 4));
                 i++ ) {

                regNum = look->regs[ i ];
                match = matchKeys( nub, keys,
                                    look->defaultMask, regNum & 0xfc );
		if( 0 == (1 & regNum))
		    break;
	    }
        }
    }

    return( match );
}

bool IOPCIBridge::matchNubWithPropertyTable( IOService * nub,
					    OSDictionary * table,
                                            SInt32 * score )
{
    bool	matches;

    matches = pciMatchNub( (IOPCIDevice *) nub, table, score);

    return( matches );
}

bool IOPCIBridge::compareNubName( const IOService * nub,
				OSString * name, OSString ** matched ) const
{
    return( IODTCompareNubName( nub, name, matched ));
}

UInt32 IOPCIBridge::findPCICapability( IOPCIAddressSpace space,
					UInt8 capabilityID, UInt8 * found )
{
    UInt32	data = 0;
    UInt8	offset = 0;

    if( found)
        *found = 0;

    if( 0 == ((kIOPCIStatusCapabilities << 16)
		& (configRead32( space, kIOPCIConfigCommand))))
	return( 0 );

    offset = configRead32( space, kIOPCIConfigCapabilitiesPtr );
    while( offset) {
	data = configRead32( space, offset );
	if( capabilityID == (data & 0xff)) {
            if( found)
                *found = offset;
	    break;
        }
	offset = (data >> 8) & 0xfc;
    }

    return( data );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOPCIBridge::createAGPSpace( IOAGPDevice * master, 
				      IOOptionBits options,
				      IOPhysicalAddress * address, 
				      IOPhysicalLength * length )
{
    return( kIOReturnUnsupported );
}

IOReturn IOPCIBridge::destroyAGPSpace( IOAGPDevice * master )
{
    return( kIOReturnUnsupported );
}

IORangeAllocator * IOPCIBridge::getAGPRangeAllocator( IOAGPDevice * master )
{
    return( 0 );
}

IOOptionBits IOPCIBridge::getAGPStatus( IOAGPDevice * master,
					IOOptionBits options = 0 )
{
    return( 0 );
}

IOReturn IOPCIBridge::commitAGPMemory( IOAGPDevice * master, 
				      IOMemoryDescriptor * memory,
				      IOByteCount agpOffset,
				      IOOptionBits options )
{
    return( kIOReturnUnsupported );
}

IOReturn IOPCIBridge::releaseAGPMemory( IOAGPDevice * master, 
				       	IOMemoryDescriptor * memory, 
					IOByteCount agpOffset,
					IOOptionBits options )
{
    return( kIOReturnUnsupported );
}

IOReturn IOPCIBridge::resetAGPDevice( IOAGPDevice * master,
                                      IOOptionBits options = 0 )
{
    return( kIOReturnUnsupported );
}

IOReturn IOPCIBridge::getAGPSpace( IOAGPDevice * master,
                                   IOPhysicalAddress * address, 
				   IOPhysicalLength * length )
{
    return( kIOReturnUnsupported );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOPCIBridge

OSDefineMetaClassAndStructors(IOPCI2PCIBridge, IOPCIBridge)
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  0);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  1);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  2);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  3);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  4);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  5);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  6);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  7);
OSMetaClassDefineReservedUnused(IOPCI2PCIBridge,  8);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOService * IOPCI2PCIBridge::probe( IOService * 	provider,
                                    SInt32 *		score )
{

    if( 0 == (bridgeDevice = OSDynamicCast( IOPCIDevice, provider)))
	return( 0 );

    *score 		-= 100;

    return( this );
}

enum {
    kPCI2PCIBusNumbers		= 0x18,
    kPCI2PCIIORange		= 0x1c,
    kPCI2PCIMemoryRange		= 0x20,
    kPCI2PCIPrefetchMemoryRange	= 0x24,
    kPCI2PCIUpperIORange	= 0x30
};

bool IOPCI2PCIBridge::configure( IOService * provider )
{
    UInt32	end;
    UInt32	start;
    bool 	ok;

    end = bridgeDevice->configRead32( kPCI2PCIMemoryRange );
    if( end ) {
	start = (end & 0xfff0) << 16;
	end |= 0x000fffff;
	ok = addBridgeMemoryRange( start, end - start + 1, false );
    }

    end = bridgeDevice->configRead32( kPCI2PCIPrefetchMemoryRange );
    if( end) {
	start = (end & 0xfff0) << 16;
	end |= 0x000fffff;
	ok = addBridgeMemoryRange( start, end - start + 1, false );
    }

    end = bridgeDevice->configRead32( kPCI2PCIIORange );
    if( end) {
	start = (end & 0xf0) << 8;
	end = (end & 0xffff) | 0xfff;
	ok = addBridgeIORange( start, end - start + 1 );
    }
    
    saveBridgeState();
    
    return( super::configure( provider ));
}

void IOPCI2PCIBridge::saveBridgeState( void )
{
  long cnt;
  
  for (cnt = 0; cnt < kIOPCIBridgeRegs; cnt++) {
    bridgeState[cnt] = bridgeDevice->configRead32(cnt * 4);
  }
}

void IOPCI2PCIBridge::restoreBridgeState( void )
{
  long cnt;
  
  for (cnt = 0; cnt < kIOPCIBridgeRegs; cnt++) {
    bridgeDevice->configWrite32(cnt * 4, bridgeState[cnt]);
  }
}

UInt8 IOPCI2PCIBridge::firstBusNum( void )
{
    UInt32	value;

    value = bridgeDevice->configRead32( kPCI2PCIBusNumbers );

    return( (value >> 8) & 0xff );
}

UInt8 IOPCI2PCIBridge::lastBusNum( void )
{
    UInt32	value;

    value = bridgeDevice->configRead32( kPCI2PCIBusNumbers );

    return( (value >> 16) & 0xff );
}

IOPCIAddressSpace IOPCI2PCIBridge::getBridgeSpace( void )
{
    return( bridgeDevice->space );
}

UInt32 IOPCI2PCIBridge::configRead32( IOPCIAddressSpace space,
					UInt8 offset )
{
    return( bridgeDevice->configRead32( space, offset ));
}

void IOPCI2PCIBridge::configWrite32( IOPCIAddressSpace space, 
					UInt8 offset, UInt32 data )
{
    bridgeDevice->configWrite32( space, offset, data );
}

UInt16 IOPCI2PCIBridge::configRead16( IOPCIAddressSpace space,
					UInt8 offset )
{
    return( bridgeDevice->configRead16( space, offset ));
}

void IOPCI2PCIBridge::configWrite16( IOPCIAddressSpace space, 
					UInt8 offset, UInt16 data )
{
    bridgeDevice->configWrite16( space, offset, data );
}

UInt8 IOPCI2PCIBridge::configRead8( IOPCIAddressSpace space,
					UInt8 offset )
{
    return( bridgeDevice->configRead8( space, offset ));
}

void IOPCI2PCIBridge::configWrite8( IOPCIAddressSpace space, 
					UInt8 offset, UInt8 data )
{
    bridgeDevice->configWrite8( space, offset, data );
}

IODeviceMemory * IOPCI2PCIBridge::ioDeviceMemory( void )
{
    return( bridgeDevice->ioDeviceMemory());
}

bool IOPCI2PCIBridge::publishNub( IOPCIDevice * nub, UInt32 index )
{
    if( nub)
        nub->setProperty( "IOChildIndex" , index, 32 );

    return( super::publishNub( nub, index ) );
}

#ifdef __I386__

static void setupIntelPIC(IOPCIDevice *nub)
{
  OSDictionary		*propTable;
  OSArray		*controller;
  OSArray		*specifier;
  OSData		*tmpData;
  long			irq;
  extern OSSymbol	*gIntelPICName;

  propTable = nub->getPropertyTable();
  if (!propTable) return;

  do {
      // Create the interrupt specifer array.
        specifier = OSArray::withCapacity(1);
        if ( !specifier )
            break;
        irq = nub->configRead32(kIOPCIConfigInterruptLine) & 0xf;
        tmpData = OSData::withBytes(&irq, sizeof(irq));
        if ( tmpData ) {
            specifier->setObject(tmpData);
            tmpData->release();
        }

        controller = OSArray::withCapacity(1);
        if ( controller ) {
            controller->setObject(gIntelPICName);

            // Put the two arrays into the property table.
            propTable->setObject(gIOInterruptControllersKey, controller);
            controller->release();
        }
        propTable->setObject(gIOInterruptSpecifiersKey, specifier);
        specifier->release();
    } while( false );
}

#endif
