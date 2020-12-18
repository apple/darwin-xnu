/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _IOKIT_IONVRAM_H
#define _IOKIT_IONVRAM_H

#ifdef __cplusplus
#include <libkern/c++/OSPtr.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/nvram/IONVRAMController.h>
#endif /* __cplusplus */
#include <uuid/uuid.h>

#define kIODTNVRAMOFPartitionName       "common"
#define kIODTNVRAMXPRAMPartitionName    "APL,MacOS75"
#define kIODTNVRAMPanicInfoPartitonName "APL,OSXPanic"
#define kIODTNVRAMFreePartitionName     "wwwwwwwwwwww"
#define kIODTNVRAMSystemPartitionName   "secure"

#define MIN_SYNC_NOW_INTERVAL 15*60 /* Minimum 15 Minutes interval mandated */

enum IONVRAMVariableType {
	kOFVariableTypeBoolean = 1,
	kOFVariableTypeNumber,
	kOFVariableTypeString,
	kOFVariableTypeData
};

enum IONVRAMOperation {
	kIONVRAMOperationRead,
	kIONVRAMOperationWrite,
	kIONVRAMOperationDelete,
	kIONVRAMOperationObliterate,
	kIONVRAMOperationReset
};

enum {
	// Deprecated but still used in AppleEFIRuntime for now
	kOFVariablePermRootOnly = 0,
	kOFVariablePermUserRead,
	kOFVariablePermUserWrite,
	kOFVariablePermKernelOnly
};

#ifdef __cplusplus

class IODTNVRAMVariables;

class IODTNVRAM : public IOService
{
	OSDeclareDefaultStructors(IODTNVRAM);

private:
	IONVRAMController      *_nvramController;
	OSPtr<const OSSymbol>  _registryPropertiesKey;
	UInt8                  *_nvramImage;
	IOLock                 *_variableLock;
	IOLock                 *_controllerLock;
	UInt32                 _commonPartitionOffset;
	UInt32                 _commonPartitionSize;
	UInt8                  *_commonImage;
	IODTNVRAMVariables     *_commonService;
	OSPtr<OSDictionary>    _commonDict;
	UInt32                 _systemPartitionOffset;
	UInt32                 _systemPartitionSize;
	UInt8                  *_systemImage;
	IODTNVRAMVariables     *_systemService;
	OSPtr<OSDictionary>    _systemDict;
	OSPtr<OSDictionary>    _nvramPartitionOffsets;
	OSPtr<OSDictionary>    _nvramPartitionLengths;
	bool                   _systemPanicked;
	SInt32                 _lastDeviceSync;
	bool                   _freshInterval;
	bool                   _isProxied;
	UInt32                 _nvramSize;

	virtual UInt8 calculatePartitionChecksum(UInt8 *partitionHeader);
	virtual IOReturn initVariables(void);
	virtual UInt32 getOFVariableType(const char *propName) const;
	virtual UInt32 getOFVariableType(const OSSymbol *propSymbol) const;
	virtual UInt32 getOFVariablePerm(const char *propName) const;
	virtual UInt32 getOFVariablePerm(const OSSymbol *propSymbol) const;
	virtual bool getOWVariableInfo(UInt32 variableNumber, const OSSymbol **propSymbol,
	    UInt32 *propType, UInt32 *propOffset);
	virtual bool convertPropToObject(UInt8 *propName, UInt32 propNameLength,
	    UInt8 *propData, UInt32 propDataLength,
	    LIBKERN_RETURNS_RETAINED const OSSymbol **propSymbol,
	    LIBKERN_RETURNS_RETAINED OSObject **propObject);
	bool convertPropToObject(UInt8 *propName, UInt32 propNameLength,
	    UInt8 *propData, UInt32 propDataLength,
	    OSSharedPtr<const OSSymbol>& propSymbol,
	    OSSharedPtr<OSObject>& propObject);
	virtual bool convertObjectToProp(UInt8 *buffer, UInt32 *length,
	    const OSSymbol *propSymbol, OSObject *propObject);
	virtual UInt16 generateOWChecksum(UInt8 *buffer);
	virtual bool validateOWChecksum(UInt8 *buffer);
	virtual void updateOWBootArgs(const OSSymbol *key, OSObject *value);
	virtual bool searchNVRAMProperty(struct IONVRAMDescriptor *hdr,
	    UInt32 *where);

	virtual IOReturn readNVRAMPropertyType0(IORegistryEntry *entry,
	    const OSSymbol **name,
	    OSData **value);
	virtual IOReturn writeNVRAMPropertyType0(IORegistryEntry *entry,
	    const OSSymbol *name,
	    OSData * value);

	virtual OSPtr<OSData> unescapeBytesToData(const UInt8 *bytes, UInt32 length);
	virtual OSPtr<OSData> escapeDataToData(OSData * value);

	virtual IOReturn readNVRAMPropertyType1(IORegistryEntry *entry,
	    const OSSymbol **name,
	    OSData **value);
	virtual IOReturn writeNVRAMPropertyType1(IORegistryEntry *entry,
	    const OSSymbol *name,
	    OSData *value);

	UInt32 getNVRAMSize(void);
	void initNVRAMImage(void);
	void initProxyData(void);
	IOReturn serializeVariables(void);
	IOReturn setPropertyInternal(const OSSymbol *aKey, OSObject *anObject);
	IOReturn removePropertyInternal(const OSSymbol *aKey);
	IOReturn chooseDictionary(IONVRAMOperation operation, const uuid_t *varGuid,
	    const char *variableName, OSDictionary **dict) const;
	bool handleSpecialVariables(const char *name, uuid_t *guid, OSObject *obj, IOReturn *error);

public:
	virtual bool init(IORegistryEntry *old, const IORegistryPlane *plane) APPLE_KEXT_OVERRIDE;

	virtual void registerNVRAMController(IONVRAMController *nvram);

	virtual void sync(void);
	virtual IOReturn syncOFVariables(void);

	virtual bool serializeProperties(OSSerialize *s) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const char *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject *getProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject *getProperty(const char *aKey) const APPLE_KEXT_OVERRIDE;
	virtual bool setProperty(const OSSymbol *aKey, OSObject *anObject) APPLE_KEXT_OVERRIDE;
	virtual void removeProperty(const OSSymbol *aKey) APPLE_KEXT_OVERRIDE;
	virtual IOReturn setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;

	virtual IOReturn readXPRAM(IOByteCount offset, UInt8 *buffer,
	    IOByteCount length);
	virtual IOReturn writeXPRAM(IOByteCount offset, UInt8 *buffer,
	    IOByteCount length);

	virtual IOReturn readNVRAMProperty(IORegistryEntry *entry,
	    const OSSymbol **name,
	    OSData **value);
	virtual IOReturn writeNVRAMProperty(IORegistryEntry *entry,
	    const OSSymbol *name,
	    OSData *value);

	virtual OSDictionary *getNVRAMPartitions(void);

	virtual IOReturn readNVRAMPartition(const OSSymbol *partitionID,
	    IOByteCount offset, UInt8 *buffer,
	    IOByteCount length);

	virtual IOReturn writeNVRAMPartition(const OSSymbol *partitionID,
	    IOByteCount offset, UInt8 *buffer,
	    IOByteCount length);

	virtual IOByteCount savePanicInfo(UInt8 *buffer, IOByteCount length);
	virtual bool safeToSync(void);
	void syncInternal(bool rateLimit);
};

#endif /* __cplusplus */

#endif /* !_IOKIT_IONVRAM_H */
