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


#ifndef _IOKIT_APPLEI386PCI_H
#define _IOKIT_APPLEI386PCI_H

#include <IOKit/pci/IOPCIBridge.h>

class AppleI386PCI : public IOPCIBridge
{
    OSDeclareDefaultStructors(AppleI386PCI)

    IOSimpleLock *	lock;
    IODeviceMemory *	ioMemory;

    UInt8		maxBusNum;        /* Highest valid Bus Number */
    UInt8		maxDevNum;        /* Highest valid Device Number */
    bool		BIOS16Present;    /* booter found PCI BIOS 16 */
    bool		configMethod1;    /* host bridge supports CM1 */
    bool		configMethod2;    /* host bridge supports CM2 */
    bool		specialCycle1;    /* host bridge supports SC1 */
    bool		specialCycle2;    /* host bridge supports SC2 */
    bool		BIOS32Present;    /* init found PCI BIOS 32 */
    void		*BIOS32Entry;     /* Points to 32 bit PCI entry pt */
    int			majorVersion;     /* Packed BCD Major Rev#: 0x02 */
    int			minorVersion;     /* Packed BCD Minor Rev#: 0x00 */

private:
    virtual UInt32 configRead32Method1( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite32Method1( IOPCIAddressSpace space,
                                        UInt8 offset, UInt32 data );
    virtual UInt16 configRead16Method1( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite16Method1( IOPCIAddressSpace space,
                                        UInt8 offset, UInt16 data );
    virtual UInt8 configRead8Method1( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite8Method1( IOPCIAddressSpace space,
                                        UInt8 offset, UInt8 data );

    virtual UInt32 configRead32Method2( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite32Method2( IOPCIAddressSpace space,
                                        UInt8 offset, UInt32 data );
    virtual UInt16 configRead16Method2( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite16Method2( IOPCIAddressSpace space,
                                        UInt8 offset, UInt16 data );
    virtual UInt8 configRead8Method2( IOPCIAddressSpace space,
                                        UInt8 offset );
    virtual void configWrite8Method2( IOPCIAddressSpace space,
                                        UInt8 offset, UInt8 data );

    virtual IOPCIAddressSpace getBridgeSpace( void );

protected:
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
};

#endif /* ! _IOKIT_APPLEI386PCI_H */

