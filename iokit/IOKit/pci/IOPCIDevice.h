/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#ifndef _IOKIT_IOPCIDEVICE_H
#define _IOKIT_IOPCIDEVICE_H

#warning IOPCIDevice.h moved to IOPCIFamily project
#warning IOPCIDevice.h will be removed from xnu; do not edit or add new usage

#include <IOKit/IOService.h>

union IOPCIAddressSpace {
    UInt32		bits;
    struct {
#ifdef __BIG_ENDIAN__
        unsigned int	reloc:1;
        unsigned int	prefetch:1;
        unsigned int	t:1;
        unsigned int	resv:3;
        unsigned int	space:2;
        unsigned int	busNum:8;
        unsigned int	deviceNum:5;
        unsigned int	functionNum:3;
        unsigned int	registerNum:8;
#elif defined(__LITTLE_ENDIAN__)
        unsigned int	registerNum:8;
        unsigned int	functionNum:3;
        unsigned int	deviceNum:5;
        unsigned int	busNum:8;
        unsigned int	space:2;
        unsigned int	resv:3;
        unsigned int	t:1;
        unsigned int	prefetch:1;
        unsigned int	reloc:1;
#endif
    } s;
};

class IOPCIDevice : public IOService
{
    OSDeclareDefaultStructors(IOPCIDevice)

    friend class IOPCIBridge;
    friend class IOPCI2PCIBridge;

protected:
    IOPCIBridge *	parent;
    IOMemoryMap *	ioMap;
    OSObject *          slotNameProperty;

    struct ExpansionData { };

    ExpansionData *reserved;

public:
    IOPCIAddressSpace   space;
    UInt32	*	savedConfig;

public:

    virtual bool attach( IOService * provider );
    virtual void detach( IOService * provider );
    virtual IOReturn setPowerState( unsigned long, IOService * );
    virtual bool compareName( OSString * name, OSString ** matched = 0 ) const;
    virtual bool matchPropertyTable( OSDictionary *	table,
                                     SInt32       *	score );
    virtual IOService * matchLocation( IOService * client );
    virtual IOReturn getResources( void );

    /* Config space accessors */

    virtual UInt32 configRead32( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite32( IOPCIAddressSpace space,
					UInt8 offset, UInt32 data );
    virtual UInt16 configRead16( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite16( IOPCIAddressSpace space,
					UInt8 offset, UInt16 data );
    virtual UInt8 configRead8( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite8( IOPCIAddressSpace space,
					UInt8 offset, UInt8 data );

    virtual UInt32 configRead32( UInt8 offset );
    virtual UInt16 configRead16( UInt8 offset );
    virtual UInt8 configRead8( UInt8 offset );
    virtual void configWrite32( UInt8 offset, UInt32 data );
    virtual void configWrite16( UInt8 offset, UInt16 data );
    virtual void configWrite8( UInt8 offset, UInt8 data );

    virtual IOReturn saveDeviceState( IOOptionBits options = 0 );
    virtual IOReturn restoreDeviceState( IOOptionBits options = 0 );
    virtual UInt32 setConfigBits( UInt8 offset, UInt32 mask, UInt32 value );

    virtual bool setMemoryEnable( bool enable );
    virtual bool setIOEnable( bool enable, bool exclusive = false );
    virtual bool setBusMasterEnable( bool enable );
    virtual UInt32 findPCICapability( UInt8 capabilityID, UInt8 * offset = 0 );
    virtual UInt8 getBusNumber( void );
    virtual UInt8 getDeviceNumber( void );
    virtual UInt8 getFunctionNumber( void );
    virtual IODeviceMemory * getDeviceMemoryWithRegister( UInt8 reg );
    virtual IOMemoryMap * mapDeviceMemoryWithRegister( UInt8 reg,
						IOOptionBits options = 0 );
    virtual IODeviceMemory * ioDeviceMemory( void );
    virtual void ioWrite32( UInt16 offset, UInt32 value,
				IOMemoryMap * map = 0 );
    virtual void ioWrite16( UInt16 offset, UInt16 value,
				IOMemoryMap * map = 0 );
    virtual void ioWrite8( UInt16 offset, UInt8 value,
				IOMemoryMap * map = 0 );
    virtual UInt32 ioRead32( UInt16 offset, IOMemoryMap * map = 0 );
    virtual UInt16 ioRead16( UInt16 offset, IOMemoryMap * map = 0 );
    virtual UInt8 ioRead8( UInt16 offset, IOMemoryMap * map = 0 );

    // Unused Padding
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  0);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  1);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  2);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  3);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  4);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  5);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  6);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  7);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  8);
    OSMetaClassDeclareReservedUnused(IOPCIDevice,  9);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 10);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 11);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 12);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 13);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 14);
    OSMetaClassDeclareReservedUnused(IOPCIDevice, 15);
};

#endif /* ! _IOKIT_IOPCIDEVICE_H */
