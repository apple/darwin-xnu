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

#include <architecture/i386/kernBootStruct.h>
#include <architecture/i386/pio.h>

#include "AppleI386PCI.h"

#include <assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOPCIBridge

OSDefineMetaClassAndStructors(AppleI386PCI, IOPCIBridge)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleI386PCI::start( IOService * provider )
{
    OSData *		prop;
    PCI_bus_info_t *	info;

    if( 0 == (lock = IOSimpleLockAlloc()))
	return( false );

    prop = (OSData *) provider->getProperty("pci-bus-info");
    if( 0 == prop)
	return( false);

    info = (PCI_bus_info_t *) prop->getBytesNoCopy();

    maxBusNum = info->maxBusNum;
    maxDevNum = 0;
    majorVersion = info->majorVersion;
    minorVersion = info->minorVersion;
    BIOS16Present = info->BIOSPresent;
    BIOS32Present = false;
    BIOS32Entry   = 0x00000000;
    configMethod1 = info->u_bus.s.configMethod1;
    configMethod2 = info->u_bus.s.configMethod2;
    specialCycle1 = info->u_bus.s.specialCycle1;
    specialCycle2 = info->u_bus.s.specialCycle2;

        /*
         if ((BIOS16Present) & !(configMethod1 | configMethod2)) {
             // This is a PCI system, but neither method is supported
             // Lets try them both just in case (ala NEC ExpressII P60)
             if (!(configMethod1 = [self test_M1]))
                 configMethod2 = [self test_M2];
         }
         */

#define IFYES(b, s) ((b) ? s : "")
    IOLog("PCI Ver=%x.%02x BusCount=%d Features=[ %s%s%s%s%s%s]\n",
	majorVersion, minorVersion, maxBusNum+1,
	IFYES(BIOS16Present, "BIOS16 "), IFYES(BIOS32Present, "BIOS32 "),
	IFYES(configMethod1, "CM1 "), IFYES(configMethod2, "CM2 "),
	IFYES(specialCycle1, "SC1 "), IFYES(specialCycle2, "SC2 ") );

    if (configMethod1)
        maxDevNum = 31;
    else if (configMethod2)
        maxDevNum = 15;
    else
	return( false );

    ioMemory = IODeviceMemory::withRange( 0, 65536 );
    if( !ioMemory)
	return( false);
    ioMemory->setMapping( kernel_task, 0 );	/* mapped to zero in IO space */

    return( super::start( provider));
}

bool AppleI386PCI::configure( IOService * provider )
{
    bool ok;

    ok = addBridgeMemoryRange( 0x80000000, 0x7f000000, true );
    ok = addBridgeIORange( 0, 0x10000 );

    return( super::configure( provider ));
}

void AppleI386PCI::free()
{
    if( ioMemory)
	ioMemory->release();
    if( lock)
	IOSimpleLockFree( lock);

    super::free();
}

IODeviceMemory * AppleI386PCI::ioDeviceMemory( void )
{
    return( ioMemory);
}


UInt8 AppleI386PCI::firstBusNum( void )
{
    return( 0 );
}

UInt8 AppleI386PCI::lastBusNum( void )
{
    return( firstBusNum() );
}

IOPCIAddressSpace AppleI386PCI::getBridgeSpace( void )
{
    IOPCIAddressSpace	space;

    space.bits = 0;

    return( space );
}

/* defines for Configuration Method #1 (PCI 2.0 Spec, sec 3.6.4.1.1) */
#define PCI_CONFIG_ADDRESS      0x0cf8
#define PCI_CONFIG_DATA         0x0cfc

/* defines for Configuration Method #2 (PCI 2.0 Spec, sec 3.6.4.1.3) */
#define PCI_CSE_REGISTER        0x0cf8
#define PCI_BUS_FORWARD         0x0cfa

#define	PCI_DEFAULT_DATA	0xffffffff

#if 0

- (BOOL) test_M1
{
    unsigned long address, data;

    for (address = 0x80000000; address < 0x80010000; address += 0x800) {
        outl (PCI_CONFIG_ADDRESS, address);
        if (inl (PCI_CONFIG_ADDRESS) != address) {
            return NO;
        }
        data = inl(PCI_CONFIG_DATA);
        if ((data != PCI_DEFAULT_DATA) && (data != 0x00)) {
            outl (PCI_CONFIG_ADDRESS, 0);
            return YES;
        }
    }

    outl (PCI_CONFIG_ADDRESS, 0);
    return NO;
}

- (BOOL) test_M2
{
    unsigned long address, data;

    /*  Enable configuration space at I/O ports Cxxx.  */

    outb (PCI_CSE_REGISTER, 0xF0);
    if (inb (PCI_CSE_REGISTER) != 0xF0) {
        return NO;
    }

    outb (PCI_BUS_FORWARD, 0x00);
    if (inb (PCI_BUS_FORWARD) != 0x00) {
        return NO;
    }
    /*  Search all devices on the bus.  */
    for (address = 0xc000; address <= 0xcfff; address += 0x100) {
        data = inl(address);
        if ((data != PCI_DEFAULT_DATA) && (data != 0x00)) {
            outb (PCI_CSE_REGISTER, 0);
            return YES;
        }
    }

    outb (PCI_CSE_REGISTER, 0);
    return NO;
}
#endif

UInt32 AppleI386PCI::configRead32Method1( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    IOPCIAddressSpace	addrCycle;
    UInt32		data = PCI_DEFAULT_DATA;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        data = inl( PCI_CONFIG_DATA);

    outl( PCI_CONFIG_ADDRESS, 0);

    return( data );
}


void AppleI386PCI::configWrite32Method1( IOPCIAddressSpace space, 
					UInt8 offset, UInt32 data )
{
    IOPCIAddressSpace	addrCycle;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        outl(PCI_CONFIG_DATA, data);

    outl( PCI_CONFIG_ADDRESS, 0);
}

UInt16 AppleI386PCI::configRead16Method1( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    IOPCIAddressSpace	addrCycle;
    UInt16		data = 0xffff;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        data = inw( PCI_CONFIG_DATA);

    outl( PCI_CONFIG_ADDRESS, 0);

    return( data );
}


void AppleI386PCI::configWrite16Method1( IOPCIAddressSpace space, 
					UInt8 offset, UInt16 data )
{
    IOPCIAddressSpace	addrCycle;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        outw(PCI_CONFIG_DATA, data);

    outl( PCI_CONFIG_ADDRESS, 0);
}

UInt8 AppleI386PCI::configRead8Method1( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    IOPCIAddressSpace	addrCycle;
    UInt8		data = 0xff;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        data = inb( PCI_CONFIG_DATA);

    outl( PCI_CONFIG_ADDRESS, 0);

    return( data );
}


void AppleI386PCI::configWrite8Method1( IOPCIAddressSpace space, 
					UInt8 offset, UInt8 data )
{
    IOPCIAddressSpace	addrCycle;

    addrCycle = space;
    addrCycle.s.reloc = 1;
    addrCycle.s.registerNum = offset;

    outl( PCI_CONFIG_ADDRESS, addrCycle.bits);
    if (inl( PCI_CONFIG_ADDRESS) == addrCycle.bits)
        outb(PCI_CONFIG_DATA, data);

    outl( PCI_CONFIG_ADDRESS, 0);
}

UInt32 AppleI386PCI::configRead32Method2( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    UInt32	data = PCI_DEFAULT_DATA;
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return( data);

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                data = inl(    0xc000
                            | (offset & 0xfc)
                            | (space.s.deviceNum << 8));
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);

    return( data );
}


void AppleI386PCI::configWrite32Method2( IOPCIAddressSpace space, 
					UInt8 offset, UInt32 data )
{
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return;

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                outl(  0xc000
                    | (offset & 0xfc)
                    | (space.s.deviceNum << 8), data);
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);
}

UInt16 AppleI386PCI::configRead16Method2( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    UInt16	data = 0xffff;
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return( data);

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                data = inw(    0xc000
                            | (offset & 0xfe)
                            | (space.s.deviceNum << 8));
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);

    return( data );
}


void AppleI386PCI::configWrite16Method2( IOPCIAddressSpace space, 
					UInt8 offset, UInt16 data )
{
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return;

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                outw(  0xc000
                    | (offset & 0xfe)
                    | (space.s.deviceNum << 8), data);
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);
}


UInt8 AppleI386PCI::configRead8Method2( IOPCIAddressSpace space,
                                            UInt8 offset )
{
    UInt16	data = 0xffff;
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return( data);

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                data = inb(    0xc000
                            | (offset)
                            | (space.s.deviceNum << 8));
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);

    return( data );
}


void AppleI386PCI::configWrite8Method2( IOPCIAddressSpace space, 
					UInt8 offset, UInt8 data )
{
    UInt8	cse;

    if( space.s.deviceNum > 15)
	return;

    cse = 0xf0 | (space.s.functionNum << 1);
    outb( PCI_CSE_REGISTER, cse);
    if (inb( PCI_CSE_REGISTER) == cse) {
        outb( PCI_BUS_FORWARD, space.s.busNum);
            if (inb( PCI_BUS_FORWARD) == space.s.busNum) {
                outb(  0xc000
                    | (offset)
                    | (space.s.deviceNum << 8), data);
        }
        outb( PCI_BUS_FORWARD, 0x00);
    }
    outb( PCI_CSE_REGISTER, 0x00);
}


UInt32 AppleI386PCI::configRead32( IOPCIAddressSpace space,
					UInt8 offset )
{
    IOInterruptState ints;
    UInt32 retval;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	retval = configRead32Method1( space, offset );
    else
	retval = configRead32Method2( space, offset );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return(retval);
}

void AppleI386PCI::configWrite32( IOPCIAddressSpace space, 
					UInt8 offset, UInt32 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	configWrite32Method1( space, offset, data );
    else
	configWrite32Method2( space, offset, data );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

UInt16 AppleI386PCI::configRead16( IOPCIAddressSpace space,
					UInt8 offset )
{
    IOInterruptState ints;
    UInt16 retval;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	retval = configRead16Method1( space, offset );
    else
	retval = configRead16Method2( space, offset );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return(retval);
}

void AppleI386PCI::configWrite16( IOPCIAddressSpace space, 
					UInt8 offset, UInt16 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	configWrite16Method1( space, offset, data );
    else
	configWrite16Method2( space, offset, data );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

UInt8 AppleI386PCI::configRead8( IOPCIAddressSpace space,
					UInt8 offset )
{
    IOInterruptState ints;
    UInt8 retval;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	retval = configRead8Method1( space, offset );
    else
	retval = configRead8Method2( space, offset );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
    return(retval);
}

void AppleI386PCI::configWrite8( IOPCIAddressSpace space, 
					UInt8 offset, UInt8 data )
{
    IOInterruptState ints;

    ints = IOSimpleLockLockDisableInterrupt( lock );

    if( configMethod1)
	configWrite8Method1( space, offset, data );
    else
	configWrite8Method2( space, offset, data );

    IOSimpleLockUnlockEnableInterrupt( lock, ints );
}

