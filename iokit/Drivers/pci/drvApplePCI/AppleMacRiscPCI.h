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
 *
 */


#ifndef _IOKIT_APPLEMACRISCPCI_H
#define _IOKIT_APPLEMACRISCPCI_H

#include <IOKit/pci/IOPCIBridge.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

enum {
    kBridgeSelfDevice = 11
};

enum {
    kMacRISCAddressSelect 	= 0x48
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class AppleMacRiscPCI : public IOPCIBridge
{
    OSDeclareDefaultStructors(AppleMacRiscPCI)

protected:
    IOSimpleLock *		lock;
    IODeviceMemory *		ioMemory;
    IOMemoryMap *		configAddrMap;
    IOMemoryMap *		configDataMap;

    volatile UInt32	*	configAddr;
    volatile UInt8	*	configData;

    UInt16			coarseAddressMask;
    UInt16			fineAddressMask;
    UInt8			primaryBus;
    UInt8			configDataOffsetMask;

    inline bool setConfigSpace( IOPCIAddressSpace space, UInt8 offset );
    virtual UInt8 firstBusNum( void );
    virtual UInt8 lastBusNum( void );

public:
    virtual bool start(	IOService * provider );
    virtual bool configure( IOService * provider );

    virtual void free();

    virtual IODeviceMemory * ioDeviceMemory( void );

    virtual UInt32 configRead32( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite32( IOPCIAddressSpace space,
					UInt8 offset, UInt32 data );
    virtual UInt16 configRead16( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite16( IOPCIAddressSpace space,
					UInt8 offset, UInt16 data );
    virtual UInt8 configRead8( IOPCIAddressSpace space, UInt8 offset );
    virtual void configWrite8( IOPCIAddressSpace space,
					UInt8 offset, UInt8 data );

    virtual IOPCIAddressSpace getBridgeSpace( void );
};

class AppleMacRiscVCI : public AppleMacRiscPCI
{
    OSDeclareDefaultStructors(AppleMacRiscVCI)

public:
    virtual bool configure( IOService * provider );

    virtual IODeviceMemory * ioDeviceMemory( void );

};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Definitions of UniNorth Target config registers */
enum {
    kUniNGART_BASE		= 0x8c,
    kUniNAGP_BASE		= 0x90,
    kUniNGART_CTRL		= 0x94,
    kUniNINTERNAL_STATUS	= 0x98
};
enum {
    kGART_INV			= 0x00000001,
    kGART_EN			= 0x00000100,
    kGART_2xRESET		= 0x00010000
};

class IORangeAllocator;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class AppleMacRiscAGP : public AppleMacRiscPCI
{
    OSDeclareDefaultStructors(AppleMacRiscAGP)

protected:
    IORangeAllocator *	agpRange;
    UInt32		agpBaseIndex;
    IOPhysicalAddress	systemBase;
    IOPhysicalLength	systemLength;
    volatile UInt32 *	gartArray;
    IOByteCount		gartLength;
    UInt8		targetAGPRegisters;

private:
    virtual IOReturn setAGPEnable( IOAGPDevice * master, bool enable,
					IOOptionBits options = 0 );

public:

    virtual bool configure( IOService * provider );

    virtual IOPCIDevice * createNub( OSDictionary * from );

    virtual IOReturn saveDeviceState( IOPCIDevice * device,
                                      IOOptionBits options = 0 );
    virtual IOReturn restoreDeviceState( IOPCIDevice * device,
                                         IOOptionBits options = 0 );

    virtual IOReturn createAGPSpace( IOAGPDevice * master, 
				     IOOptionBits options,
				     IOPhysicalAddress * address, 
				     IOPhysicalLength * length );

    virtual IOReturn destroyAGPSpace( IOAGPDevice * master );

    virtual IORangeAllocator * getAGPRangeAllocator( IOAGPDevice * master );

    virtual IOOptionBits getAGPStatus( IOAGPDevice * master,
				      IOOptionBits options = 0 );
    virtual IOReturn resetAGPDevice( IOAGPDevice * master,
                                     IOOptionBits options = 0 );

    virtual IOReturn getAGPSpace( IOAGPDevice * master,
                                  IOPhysicalAddress * address, 
				  IOPhysicalLength * length );

    virtual IOReturn commitAGPMemory( IOAGPDevice * master, 
				      IOMemoryDescriptor * memory,
				      IOByteCount agpOffset,
				      IOOptionBits options = 0 );

    virtual IOReturn releaseAGPMemory( IOAGPDevice * master, 
				       IOMemoryDescriptor * memory,
				       IOByteCount agpOffset,
				       IOOptionBits options = 0 );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#endif /* ! _IOKIT_APPLEMACRISCPCI_H */

