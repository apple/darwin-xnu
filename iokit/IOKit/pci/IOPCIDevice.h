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


#ifndef _IOKIT_IOPCIDEVICE_H
#define _IOKIT_IOPCIDEVICE_H

#include <IOKit/IOService.h>

/* Definitions of PCI Config Registers */
enum {
    kIOPCIConfigVendorID		= 0x00,
    kIOPCIConfigDeviceID		= 0x02,
    kIOPCIConfigCommand			= 0x04,
    kIOPCIConfigStatus			= 0x06,
    kIOPCIConfigRevisionID		= 0x08,
    kIOPCIConfigClassCode		= 0x09,
    kIOPCIConfigCacheLineSize		= 0x0C,
    kIOPCIConfigLatencyTimer		= 0x0D,
    kIOPCIConfigHeaderType		= 0x0E,
    kIOPCIConfigBIST			= 0x0F,
    kIOPCIConfigBaseAddress0		= 0x10,
    kIOPCIConfigBaseAddress1		= 0x14,
    kIOPCIConfigBaseAddress2		= 0x18,
    kIOPCIConfigBaseAddress3		= 0x1C,
    kIOPCIConfigBaseAddress4		= 0x20,
    kIOPCIConfigBaseAddress5		= 0x24,
    kIOPCIConfigCardBusCISPtr		= 0x28,
    kIOPCIConfigSubSystemVendorID	= 0x2C,
    kIOPCIConfigSubSystemID		= 0x2E,
    kIOPCIConfigExpansionROMBase	= 0x30,
    kIOPCIConfigCapabilitiesPtr		= 0x34,
    kIOPCIConfigInterruptLine		= 0x3C,
    kIOPCIConfigInterruptPin		= 0x3D,
    kIOPCIConfigMinimumGrant		= 0x3E,
    kIOPCIConfigMaximumLatency		= 0x3F
};

/* Definitions of Capabilities PCI Config Register */
enum {
    kIOPCICapabilityIDOffset		= 0x00,
    kIOPCINextCapabilityOffset		= 0x01,
    kIOPCIPowerManagementCapability	= 0x01,
    kIOPCIAGPCapability        		= 0x02
};

/* Space definitions */
enum {
    kIOPCIConfigSpace		= 0,
    kIOPCIIOSpace		= 1,
    kIOPCI32BitMemorySpace	= 2,
    kIOPCI64BitMemorySpace	= 3
};

/* Command register definitions */
enum {
    kIOPCICommandIOSpace		= 0x0001,
    kIOPCICommandMemorySpace		= 0x0002,
    kIOPCICommandBusMaster		= 0x0004,
    kIOPCICommandSpecialCycles		= 0x0008,
    kIOPCICommandMemWrInvalidate	= 0x0010,
    kIOPCICommandPaletteSnoop		= 0x0020,
    kIOPCICommandParityError		= 0x0040,
    kIOPCICommandAddressStepping	= 0x0080,
    kIOPCICommandSERR			= 0x0100,
    kIOPCICommandFastBack2Back		= 0x0200
};

/* Status register definitions */
enum {
    kIOPCIStatusCapabilities		= 0x0010,
    kIOPCIStatusPCI66			= 0x0020,
    kIOPCIStatusUDF			= 0x0040,
    kIOPCIStatusFastBack2Back		= 0x0080,
    kIOPCIStatusDevSel0			= 0x0000,
    kIOPCIStatusDevSel1			= 0x0200,
    kIOPCIStatusDevSel2			= 0x0400,
    kIOPCIStatusDevSel3			= 0x0600,
    kIOPCIStatusTargetAbortCapable	= 0x0800,
    kIOPCIStatusTargetAbortActive	= 0x1000,
    kIOPCIStatusMasterAbortActive	= 0x2000,
    kIOPCIStatusSERRActive		= 0x4000,
    kIOPCIStatusParityErrActive		= 0x8000
};

union IOPCIAddressSpace {
    UInt32		bits;
    struct {
#if __BIG_ENDIAN__
        unsigned int	reloc:1;
        unsigned int	prefetch:1;
        unsigned int	t:1;
        unsigned int	resv:3;
        unsigned int	space:2;
        unsigned int	busNum:8;
        unsigned int	deviceNum:5;
        unsigned int	functionNum:3;
        unsigned int	registerNum:8;
#elif __LITTLE_ENDIAN__
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

struct IOPCIPhysicalAddress {
    IOPCIAddressSpace	physHi;
    UInt32		physMid;
    UInt32		physLo;
    UInt32		lengthHi;
    UInt32		lengthLo;
};

// IOPCIDevice matching property names
#define kIOPCIMatchKey			"IOPCIMatch"
#define kIOPCIPrimaryMatchKey		"IOPCIPrimaryMatch"
#define kIOPCISecondaryMatchKey		"IOPCISecondaryMatch"
#define kIOPCIClassMatchKey		"IOPCIClassMatch"

// property to control PCI default config space save on sleep
#define kIOPMPCIConfigSpaceVolatileKey	"IOPMPCIConfigSpaceVolatile"

enum {
    kIOPCIDevicePowerStateCount = 3,
    kIOPCIDeviceOffState	= 0,
    kIOPCIDeviceOnState		= 2
};

/*! @class IOPCIDevice : public IOService
    @abstract An IOService class representing a PCI device.
    @discussion The discovery of an PCI device by the PCI bus family results in an instance of the IOPCIDevice being created and published. It provides services for looking up and mapping memory mapped hardware, and access to the PCI configuration and I/O spaces. 

<br><br>Matching Supported by IOPCIDevice<br><br>

Two types of matching are available, OpenFirmware name matching and PCI register matching. Currently, only one of these two matching schemes can be used in the same property table.

<br><br>OpenFirmware Name Matching<br><br>

IOService performs matching based on the IONameMatch property (see IOService). IOPCIDevices created with OpenFirmware device tree entries will name match based on the standard OpenFirmware name matching properties.

<br><br>PCI Register Matching<br><br>

A PCI device driver can also match on the values of certain config space registers.

In each case, several matching values can be specified, and an optional mask for the value of the config space register may follow the value, preceded by an '&' character.
<br>
<br>
	kIOPCIMatchKey, "IOPCIMatch"
<br>
The kIOPCIMatchKey property matches the vendor and device ID (0x00) register, or the subsystem register (0x2c).
<br>
<br>
	kIOPCIPrimaryMatchKey, "IOPCIPrimaryMatch"
<br>
The kIOPCIPrimaryMatchKey property matches the vendor and device ID (0x00) register.
<br>
<br>
	kIOPCISecondaryMatchKey, "IOPCISecondaryMatch"
<br>
The kIOPCISecondaryMatchKey property matches the subsystem register (0x2c).
<br>
<br>
	kIOPCIClassMatchKey, "IOPCIClassMatch"
<br>
The kIOPCIClassMatchKey property matches the class code register (0x08). The default mask for this register is 0xffffff00.
<br>
<br>
Examples:
<br>
<br>
      &ltkey&gtIOPCIMatch&lt/key&gt		<br>
	&ltstring&gt0x00261011&lt/string&gt
<br>
Matches a device whose vendor ID is 0x1011, and device ID is 0x0026, including subsystem IDs.
<br>
<br>
      &ltkey&gtIOPCIMatch&lt/key&gt		<br>
	&ltstring&gt0x00789004&0x00ffffff 0x78009004&0x0xff00ffff&lt/string&gt
<br>
Matches with any device with a vendor ID of 0x9004, and a device ID of 0xzz78 or 0x78zz, where 'z' is don't care.
<br>
<br>
      &ltkey&gtIOPCIClassMatch&lt/key&gt	<br>
	&ltstring&gt0x02000000&0xffff0000&lt/string&gt
<br>
<br>
Matches a device whose class code is 0x0200zz, an ethernet device.

*/

class IOPCIDevice : public IOService
{
    OSDeclareDefaultStructors(IOPCIDevice)

    friend class IOPCIBridge;
    friend class IOPCI2PCIBridge;

protected:
    IOPCIBridge *	parent;
    IOMemoryMap *	ioMap;
    OSObject *          slotNameProperty;

/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of the IOWorkLoop in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

public:
    IOPCIAddressSpace	space;
    UInt32	*	savedConfig;

public:
    /* IOService/IORegistryEntry methods */

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

/*! @function configRead32
    @abstract Reads a 32-bit value from the PCI device's configuration space.
    @discussion This method reads a 32-bit configuration space register on the device and returns its value.
    @param offset An 8-bit offset into configuration space, of which bits 0-1 are ignored.
    @result An 32-bit value in host byte order (big endian on PPC). */

    virtual UInt32 configRead32( UInt8 offset );

/*! @function configRead16
    @abstract Reads a 16-bit value from the PCI device's configuration space.
    @discussion This method reads a 16-bit configuration space register on the device and returns its value.
    @param offset An 8-bit offset into configuration space, of which bit 0 is ignored.
    @result An 16-bit value in host byte order (big endian on PPC). */

    virtual UInt16 configRead16( UInt8 offset );

/*! @function configRead8
    @abstract Reads a 8-bit value from the PCI device's configuration space.
    @discussion This method reads a 8-bit configuration space register on the device and returns its value.
    @param offset An 8-bit offset into configuration space.
    @result An 8-bit value. */

    virtual UInt8 configRead8( UInt8 offset );

/*! @function configWrite32
    @abstract Writes a 32-bit value to the PCI device's configuration space.
    @discussion This method write a 32-bit value to a configuration space register on the device.
    @param offset An 8-bit offset into configuration space, of which bits 0-1 are ignored.
    @param data An 32-bit value to be written in host byte order (big endian on PPC). */

    virtual void configWrite32( UInt8 offset, UInt32 data );

/*! @function configWrite16
    @abstract Writes a 16-bit value to the PCI device's configuration space.
    @discussion This method write a 16-bit value to a configuration space register on the device.
    @param offset An 8-bit offset into configuration space, of which bit 0 is ignored.
    @param data An 16-bit value to be written in host byte order (big endian on PPC). */

    virtual void configWrite16( UInt8 offset, UInt16 data );

/*! @function configWrite8
    @abstract Writes a 8-bit value to the PCI device's configuration space.
    @discussion This method write a 8-bit value to a configuration space register on the device.
    @param offset An 8-bit offset into configuration space.
    @param data An 8-bit value to be written. */

    virtual void configWrite8( UInt8 offset, UInt8 data );

    virtual IOReturn saveDeviceState( IOOptionBits options = 0 );
    virtual IOReturn restoreDeviceState( IOOptionBits options = 0 );

/*! @function setConfigBits
    @abstract Sets masked bits in a configuration space register.
    @discussion This method sets masked bits in a configuration space register on the device by reading and writing the register. The value of the masked bits before the write is returned.
    @param offset An 8-bit offset into configuration space, of which bits 0-1 are ignored.
    @param mask An 32-bit mask indicating which bits in the value parameter are valid.
    @param data An 32-bit value to be written in host byte order (big endian on PPC).
    @result The value of the register masked with the mask before the write. */
    
    virtual UInt32 setConfigBits( UInt8 offset, UInt32 mask, UInt32 value );

/*! @function setMemoryEnable
    @abstract Sets the device's memory space response.
    @discussion This method sets the memory space response bit in the device's command config space register to the passed value, and returns the previous state of the enable.
    @param enable True or false to enable or disable the memory space response.
    @result True if the memory space response was previously enabled, false otherwise. */

    virtual bool setMemoryEnable( bool enable );

/*! @function setIOEnable
    @abstract Sets the device's I/O space response.
    @discussion This method sets the I/O space response bit in the device's command config space register to the passed value, and returns the previous state of the enable. The exclusive option allows only one exclusive device on the bus to be enabled concurrently, this should be only for temporary access.
    @param enable True or false to enable or disable the I/O space response.
    @param exclusive If true, only one setIOEnable with the exclusive flag set will be allowed at a time on the bus, this should be only for temporary access.
    @result True if the I/O space response was previously enabled, false otherwise. */

    virtual bool setIOEnable( bool enable, bool exclusive = false );

/*! @function setBusMasterEnable
    @abstract Sets the device's bus master enable.
    @discussion This method sets the bus master enable bit in the device's command config space register to the passed value, and returns the previous state of the enable.
    @param enable True or false to enable or disable bus mastering.
    @result True if bus mastering was previously enabled, false otherwise. */

    virtual bool setBusMasterEnable( bool enable );

/*! @function findPCICapability
    @abstract Search configuration space for a PCI capability register.
    @discussion This method searchs the device's config space for a PCI capability register matching the passed capability ID, if the device supports PCI capabilities.
    @param capabilityID An 8-bit PCI capability ID.
    @param offset An optional pointer to return the offset into config space where the capability was found.
    @result The 32-bit value of the capability register if one was found, zero otherwise. */

    virtual UInt32 findPCICapability( UInt8 capabilityID, UInt8 * offset = 0 );

/*! @function getBusNumber
    @abstract Accessor to return the PCI device's assigned bus number.
    @discussion This method is an accessor to return the PCI device's assigned bus number.
    @result The 8-bit value of device's PCI bus number. */

    virtual UInt8 getBusNumber( void );

/*! @function getDeviceNumber
    @abstract Accessor to return the PCI device's device number.
    @discussion This method is an accessor to return the PCI device's device number.
    @result The 5-bit value of device's device number. */

    virtual UInt8 getDeviceNumber( void );

/*! @function getFunctionNumber
    @abstract Accessor to return the PCI device's function number.
    @discussion This method is an accessor to return the PCI device's function number.
    @result The 3-bit value of device's function number. */

    virtual UInt8 getFunctionNumber( void );

    /* Device memory accessors */

/*! @function getDeviceMemoryWithRegister
    @abstract Returns an instance of IODeviceMemory representing one of the device's memory mapped ranges.
    @discussion This method will return a pointer to an instance of IODeviceMemory for the physical memory range that was assigned to the configuration space base address register passed in. It is analogous to IOService::getDeviceMemoryWithIndex.
    @param reg The 8-bit configuration space register that is the base address register for the desired range.
    @result A pointer to an instance of IODeviceMemory, or zero no such range was found. The IODeviceMemory is retained by the provider, so is valid while attached, or while any mappings to it exist. It should not be released by the caller. */

    virtual IODeviceMemory * getDeviceMemoryWithRegister( UInt8 reg );

/*! @function mapDeviceMemoryWithRegister
    @abstract Maps a physical range of the device.
    @discussion This method will create a mapping for the IODeviceMemory for the physical memory range that was assigned to the configuration space base address register passed in, with IODeviceMemory::map(options). The mapping is represented by the returned instance of IOMemoryMap, which should not be released until the mapping is no longer required. This method is analogous to IOService::mapDeviceMemoryWithIndex.
    @param reg The 8-bit configuration space register that is the base address register for the desired range.
    @param options Options to be passed to the IOMemoryDescriptor::map() method.
    @result An instance of IOMemoryMap, or zero if the index is beyond the count available. The mapping should be released only when access to it is no longer required. */

    virtual IOMemoryMap * mapDeviceMemoryWithRegister( UInt8 reg,
						IOOptionBits options = 0 );

/*! @function ioDeviceMemory
    @abstract Accessor to the I/O space aperture for the bus.
    @discussion This method will return a reference to the IODeviceMemory for the I/O aperture of the bus the device is on.
    @result A pointer to an IODeviceMemory object for the I/O aperture. The IODeviceMemory is retained by the provider, so is valid while attached, or while any mappings to it exist. It should not be released by the caller. */

    virtual IODeviceMemory * ioDeviceMemory( void );

    /* I/O space accessors */

/*! @function ioWrite32
    @abstract Writes a 32-bit value to an I/O space aperture.
    @discussion This method will write a 32-bit value to a 4 byte aligned offset in an I/O space aperture. If a map object is passed in, the value is written relative to it, otherwise to the value is written relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param value The value to be written in host byte order (big endian on PPC).
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space. */

    virtual void ioWrite32( UInt16 offset, UInt32 value,
				IOMemoryMap * map = 0 );

/*! @function ioWrite16
    @abstract Writes a 16-bit value to an I/O space aperture.
    @discussion This method will write a 16-bit value to a 2 byte aligned offset in an I/O space aperture. If a map object is passed in, the value is written relative to it, otherwise to the value is written relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param value The value to be written in host byte order (big endian on PPC).
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space. */

    virtual void ioWrite16( UInt16 offset, UInt16 value,
				IOMemoryMap * map = 0 );

/*! @function ioWrite8
    @abstract Writes a 8-bit value to an I/O space aperture.
    @discussion This method will write a 8-bit value to an offset in an I/O space aperture. If a map object is passed in, the value is written relative to it, otherwise to the value is written relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param value The value to be written in host byte order (big endian on PPC).
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space. */

    virtual void ioWrite8( UInt16 offset, UInt8 value,
				IOMemoryMap * map = 0 );

/*! @function ioRead32
    @abstract Reads a 32-bit value from an I/O space aperture.
    @discussion This method will read a 32-bit value from a 4 byte aligned offset in an I/O space aperture. If a map object is passed in, the value is read relative to it, otherwise to the value is read relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space.
    @result The value read in host byte order (big endian on PPC). */

    virtual UInt32 ioRead32( UInt16 offset, IOMemoryMap * map = 0 );

/*! @function ioRead16
    @abstract Reads a 16-bit value from an I/O space aperture.
    @discussion This method will read a 16-bit value from a 2 byte aligned offset in an I/O space aperture. If a map object is passed in, the value is read relative to it, otherwise to the value is read relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space.
    @result The value read in host byte order (big endian on PPC). */

    virtual UInt16 ioRead16( UInt16 offset, IOMemoryMap * map = 0 );

/*! @function ioRead8
    @abstract Reads a 8-bit value from an I/O space aperture.
    @discussion This method will read a 8-bit value from an offset in an I/O space aperture. If a map object is passed in, the value is read relative to it, otherwise to the value is read relative to the I/O space aperture for the bus. This function encapsulates the differences between architectures in generating I/O space operations. An eieio instruction is included on PPC.
    @param offset An offset into a bus or device's I/O space aperture.
    @param map If the offset is relative to the beginning of a device's aperture, an IOMemoryMap object for that object should be passed in. Otherwise, passing zero will write the value relative to the beginning of the bus' I/O space.
    @result The value read. */

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

