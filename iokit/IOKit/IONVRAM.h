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

#ifndef _IOKIT_IONVRAM_H
#define _IOKIT_IONVRAM_H

#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/nvram/IONVRAMController.h>

enum {
  kIODTNVRAMImageSize        = 0x2000,
  kIODTNVRAMXPRAMSize        = 0x0100,
  kIODTNVRAMNameRegistrySize = 0x0400
};

enum {
  kOFVariableTypeBoolean = 1,
  kOFVariableTypeNumber,
  kOFVariableTypeString,
  kOFVariableTypeData
};

enum {
  kOFVariablePermRootOnly = 0,
  kOFVariablePermUserRead,
  kOFVariablePermUserWrite
};

class IODTNVRAM : public IOService
{
  OSDeclareDefaultStructors(IODTNVRAM);
  
private:
  IONVRAMController *_nvramController;
  const OSSymbol    *_registryPropertiesKey;
  UInt8             *_nvramImage;
  bool              _nvramImageDirty;
  UInt32            _ofPartitionOffset;
  UInt32            _ofPartitionSize;
  UInt8             *_ofImage;
  bool              _ofImageDirty;
  OSDictionary      *_ofDict;
  UInt32            _xpramPartitionOffset;
  UInt32            _xpramPartitionSize;
  UInt8             *_xpramImage;
  UInt32            _nrPartitionOffset;
  UInt32            _nrPartitionSize;
  UInt8             *_nrImage;
  
  virtual IOReturn initOFVariables(void);
  virtual IOReturn syncOFVariables(void);
  virtual UInt32 getOFVariableType(const OSSymbol *propSymbol) const;
  virtual UInt32 getOFVariablePerm(const OSSymbol *propSymbol) const;
  virtual bool getOWVariableInfo(UInt32 variableNumber, const OSSymbol **propSymbol,
				 UInt32 *propType, UInt32 *propOffset);
  virtual bool convertPropToObject(UInt8 *propName, UInt32 propNameLength,
				   UInt8 *propData, UInt32 propDataLength,
				   const OSSymbol **propSymbol,
				   OSObject **propObject);
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
  
  virtual OSData *unescapeBytesToData(UInt8 *bytes, UInt32 length);
  virtual OSData *escapeDataToData(OSData * value);

  virtual IOReturn readNVRAMPropertyType1(IORegistryEntry *entry,
					  const OSSymbol **name,
					  OSData **value);
  virtual IOReturn writeNVRAMPropertyType1(IORegistryEntry *entry,
					   const OSSymbol *name,
					   OSData *value);
  
public:
  virtual bool init(IORegistryEntry *old, const IORegistryPlane *plane);
  
  virtual void registerNVRAMController(IONVRAMController *nvram);
  
  virtual void sync(void);
  
  virtual bool serializeProperties(OSSerialize * serialize) const;
  virtual OSObject *getProperty(const OSSymbol *aKey) const;
  virtual OSObject *getProperty(const char *aKey) const;
  virtual bool setProperty(const OSSymbol *aKey, OSObject *anObject);
  virtual IOReturn setProperties(OSObject *properties);
  
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
};

#endif /* !_IOKIT_IONVRAM_H */
