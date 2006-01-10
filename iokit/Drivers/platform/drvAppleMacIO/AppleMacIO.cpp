/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 * 23 Nov 98 sdouglas created.
 */
 
#include <IOKit/system.h>
extern "C" {
#include <pexpert/pexpert.h>
}

#include <libkern/c++/OSContainers.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOPlatformExpert.h>

#include <IOKit/pci/IOPCIDevice.h>

#include <IOKit/platform/AppleMacIO.h>

#include <IOKit/ppc/IODBDMA.h>

#include <IOKit/assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndAbstractStructors(AppleMacIO, IOService);
OSMetaClassDefineReservedUnused(AppleMacIO,  0);
OSMetaClassDefineReservedUnused(AppleMacIO,  1);
OSMetaClassDefineReservedUnused(AppleMacIO,  2);
OSMetaClassDefineReservedUnused(AppleMacIO,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleMacIO::start( IOService * provider )
{
    IOPCIDevice *pciNub = (IOPCIDevice *)provider;

    if( !super::start( provider))
	return( false);

    // Make sure memory space is on.
    pciNub->setMemoryEnable(true);

    fNub = provider;
    fMemory = provider->mapDeviceMemoryWithIndex( 0 );
    if( 0 == fMemory)
	IOLog("%s: unexpected ranges\n", getName());
    else if( !selfTest())
	IOLog("Warning: AppleMacIO self test fails\n");
    PMinit();		// initialize for power management
    temporaryPowerClampOn();	// hold power on till we get children
    return( true);
}


IOService * AppleMacIO::createNub( IORegistryEntry * from )
{
    IOService *	nub;

    nub = new AppleMacIODevice;

    if( nub && !nub->init( from, gIODTPlane )) {
	nub->free();
	nub = 0;
    }

    return( nub);
}

void AppleMacIO::processNub(IOService * /*nub*/)
{
}

const char * AppleMacIO::deleteList ( void )
{
    return( "('sd', 'st', 'disk', 'tape', 'pram', 'rtc', 'mouse')" );
}

const char * AppleMacIO::excludeList( void )
{
    return( 0 );
}

void AppleMacIO::publishBelow( IORegistryEntry * root )
{
    OSCollectionIterator *	kids;
    IORegistryEntry *		next;
    IOService *			nub;

    // infanticide
    kids = IODTFindMatchingEntries( root, kIODTRecursive, deleteList() );
    if( kids) {
	while( (next = (IORegistryEntry *)kids->getNextObject())) {
	    next->detachAll( gIODTPlane);
	}
	kids->release();
    }

    // publish everything below, minus excludeList
    kids = IODTFindMatchingEntries( root, kIODTRecursive | kIODTExclusive,
					excludeList());
    if( kids) {
	while( (next = (IORegistryEntry *)kids->getNextObject())) {

            if( 0 == (nub = createNub( next )))
                continue;

            nub->attach( this );
	    
	    processNub(nub);
	    
            nub->registerService();
        }
	kids->release();
    }
}

bool AppleMacIO::compareNubName( const IOService * nub,
				OSString * name, OSString ** matched ) const
{
    return( IODTCompareNubName( nub, name, matched )
	  ||  nub->IORegistryEntry::compareName( name, matched ) );
}

IOReturn AppleMacIO::getNubResources( IOService * nub )
{
    if( nub->getDeviceMemory())
	return( kIOReturnSuccess );

    IODTResolveAddressing( nub, "reg", fNub->getDeviceMemoryWithIndex(0) );

    return( kIOReturnSuccess);
}

bool AppleMacIO::selfTest( void )
{
    IODBDMADescriptor			*dmaDescriptors;
    UInt32				dmaDescriptorsPhys;
    UInt32				i;
    UInt32				status;
    IODBDMADescriptor			*dmaDesc;
    volatile IODBDMAChannelRegisters	*ioBaseDMA;
    bool				ok = false;
    enum { 				kTestChannel = 0x8000 };

    ioBaseDMA = (volatile IODBDMAChannelRegisters *)
		(((UInt32)fMemory->getVirtualAddress())
		+ kTestChannel );

    do {
        dmaDescriptors = (IODBDMADescriptor *)IOMallocContiguous(page_size, 1, & dmaDescriptorsPhys);
        if (!dmaDescriptors)
	    continue;

        if ( (UInt32)dmaDescriptors & (page_size - 1) ) {
            IOLog("AppleMacIO::%s() - DMA Descriptor memory not page aligned!!", __FUNCTION__);
	    continue;
        }

        bzero( dmaDescriptors, page_size );

        IODBDMAReset( ioBaseDMA );

        dmaDesc = dmaDescriptors;

        IOMakeDBDMADescriptor( dmaDesc,
                            kdbdmaNop,
                            kdbdmaKeyStream0,
                            kdbdmaIntNever,
                            kdbdmaBranchNever,
                            kdbdmaWaitNever,
                            0,
                            0 );

        dmaDesc++;

        IOMakeDBDMADescriptorDep( dmaDesc,
                                kdbdmaStoreQuad,
                                kdbdmaKeySystem,
                                kdbdmaIntNever,
                                kdbdmaBranchNever,
                                kdbdmaWaitNever,
                                4,
                                dmaDescriptorsPhys+16*sizeof(IODBDMADescriptor),
                                0x12345678 );

        dmaDesc++;

        IOMakeDBDMADescriptor( dmaDesc,
                            kdbdmaStop,
                            kdbdmaKeyStream0,
                            kdbdmaIntNever,
                            kdbdmaBranchNever,
                            kdbdmaWaitNever,
                            0,
                            0 );


        for ( i = 0; (!ok) && (i < 3); i++ )
        {
            dmaDescriptors[16].operation = 0;

            IOSetDBDMACommandPtr( ioBaseDMA, dmaDescriptorsPhys );
            IODBDMAContinue( ioBaseDMA );

            IODelay( 200 );

            status = IOGetDBDMAChannelStatus( ioBaseDMA );

            if ( ((status & kdbdmaActive) == 0)
                &&  ((status & kdbdmaDead) == 0)
                    && (OSReadSwapInt32( &dmaDescriptors[16].operation, 0 ) == 0x12345678 ))
                ok = true;
        }

        IODBDMAReset( ioBaseDMA );

    } while (false);

    if (dmaDescriptors)
	IOFreeContiguous(dmaDescriptors, page_size);


    return ok;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(AppleMacIODevice, IOService);
OSMetaClassDefineReservedUnused(AppleMacIODevice,  0);
OSMetaClassDefineReservedUnused(AppleMacIODevice,  1);
OSMetaClassDefineReservedUnused(AppleMacIODevice,  2);
OSMetaClassDefineReservedUnused(AppleMacIODevice,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleMacIODevice::compareName( OSString * name,
					OSString ** matched ) const
{
  return (IODTCompareNubName(this, name, matched) ||
	  IORegistryEntry::compareName(name, matched));
}

IOService * AppleMacIODevice::matchLocation( IOService * /* client */ )
{
  return this;
}

IOReturn AppleMacIODevice::getResources( void )
{
  IOService *macIO = this;
  
  if (getDeviceMemory() != 0) return kIOReturnSuccess;
  
  while (macIO && ((macIO = macIO->getProvider()) != 0))
    if (strcmp("mac-io", macIO->getName()) == 0) break;
  
  if (macIO == 0) return kIOReturnError;
  
  IODTResolveAddressing(this, "reg", macIO->getDeviceMemoryWithIndex(0));
  
  return kIOReturnSuccess;
}

