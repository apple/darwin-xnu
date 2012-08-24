/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
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

#include <IOKit/IOLib.h>
#include <IOKit/IONVRAM.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeys.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>

#define super IOService

#define kIONVRAMPrivilege	kIOClientPrivilegeAdministrator
//#define kIONVRAMPrivilege	kIOClientPrivilegeLocalUser

OSDefineMetaClassAndStructors(IODTNVRAM, IOService);

bool IODTNVRAM::init(IORegistryEntry *old, const IORegistryPlane *plane)
{
  OSDictionary *dict;
  
  if (!super::init(old, plane)) return false;
  
  dict =  OSDictionary::withCapacity(1);
  if (dict == 0) return false;
  setPropertyTable(dict);
  
  _nvramImage = IONew(UInt8, kIODTNVRAMImageSize);
  if (_nvramImage == 0) return false;
  
  _nvramPartitionOffsets = OSDictionary::withCapacity(1);
  if (_nvramPartitionOffsets == 0) return false;
  
  _nvramPartitionLengths = OSDictionary::withCapacity(1);
  if (_nvramPartitionLengths == 0) return false;
  
  _registryPropertiesKey = OSSymbol::withCStringNoCopy("aapl,pci");
  if (_registryPropertiesKey == 0) return false;
  
  return true;
}

void IODTNVRAM::registerNVRAMController(IONVRAMController *nvram)
{
  char   partitionID[18];
  UInt32 partitionOffset, partitionLength;
  UInt32 freePartitionOffset, freePartitionSize;
  UInt32 currentLength, currentOffset = 0;
  OSNumber *partitionOffsetNumber, *partitionLengthNumber;
  
  if (_nvramController != 0) return;
  
  _nvramController = nvram;
  
  _nvramController->read(0, _nvramImage, kIODTNVRAMImageSize);
  
  // Find the offsets for the OF, XPRAM, NameRegistry and PanicInfo partitions.
  _ofPartitionOffset = 0xFFFFFFFF;
  _xpramPartitionOffset = 0xFFFFFFFF;
  _nrPartitionOffset = 0xFFFFFFFF;
  _piPartitionOffset = 0xFFFFFFFF;
  freePartitionOffset = 0xFFFFFFFF;
  freePartitionSize = 0;
  if (getPlatform()->getBootROMType()) {
    // Look through the partitions to find the OF, MacOS partitions.
    while (currentOffset < kIODTNVRAMImageSize) {
      currentLength = ((UInt16 *)(_nvramImage + currentOffset))[1] * 16;
      
      partitionOffset = currentOffset + 16;
      partitionLength = currentLength - 16;
      
      if (strncmp((const char *)_nvramImage + currentOffset + 4,
		  kIODTNVRAMOFPartitionName, 12) == 0) {
	_ofPartitionOffset = partitionOffset;
	_ofPartitionSize = partitionLength;
      } else if (strncmp((const char *)_nvramImage + currentOffset + 4,
			 kIODTNVRAMXPRAMPartitionName, 12) == 0) {
	_xpramPartitionOffset = partitionOffset;
	_xpramPartitionSize = kIODTNVRAMXPRAMSize;
	_nrPartitionOffset = _xpramPartitionOffset + _xpramPartitionSize;
	_nrPartitionSize = partitionLength - _xpramPartitionSize;
      } else if (strncmp((const char *)_nvramImage + currentOffset + 4,
			 kIODTNVRAMPanicInfoPartitonName, 12) == 0) {
	_piPartitionOffset = partitionOffset;
	_piPartitionSize = partitionLength;
      } else if (strncmp((const char *)_nvramImage + currentOffset + 4,
			 kIODTNVRAMFreePartitionName, 12) == 0) {
	freePartitionOffset = currentOffset;
	freePartitionSize = currentLength;
      } else {
	// Construct the partition ID from the signature and name.
	snprintf(partitionID, sizeof(partitionID), "0x%02x,",
		*(UInt8 *)(_nvramImage + currentOffset));
	strncpy(partitionID + 5,
		(const char *)(_nvramImage + currentOffset + 4), 12);
	partitionID[17] = '\0';
	
	partitionOffsetNumber = OSNumber::withNumber(partitionOffset, 32);
	partitionLengthNumber = OSNumber::withNumber(partitionLength, 32);
	
	// Save the partition offset and length
	_nvramPartitionOffsets->setObject(partitionID, partitionOffsetNumber);
	_nvramPartitionLengths->setObject(partitionID, partitionLengthNumber);
	
	partitionOffsetNumber->release();
	partitionLengthNumber->release();
      }
      currentOffset += currentLength;
    }
  } else {
    // Use the fixed address for old world machines.
    _ofPartitionOffset    = 0x1800;
    _ofPartitionSize      = 0x0800;
    _xpramPartitionOffset = 0x1300;
    _xpramPartitionSize   = 0x0100;
    _nrPartitionOffset    = 0x1400;
    _nrPartitionSize      = 0x0400;
  }
  
  if (_ofPartitionOffset != 0xFFFFFFFF)
    _ofImage    = _nvramImage + _ofPartitionOffset;
  if (_xpramPartitionOffset != 0xFFFFFFFF)
    _xpramImage = _nvramImage + _xpramPartitionOffset;
  if (_nrPartitionOffset != 0xFFFFFFFF)
    _nrImage    = _nvramImage + _nrPartitionOffset;
  
  if (_piPartitionOffset == 0xFFFFFFFF) {
    if (freePartitionSize > 0x20) {
      // Set the signature to 0xa1.
      _nvramImage[freePartitionOffset] = 0xa1;
      // Set the checksum to 0.
      _nvramImage[freePartitionOffset + 1] = 0;
      // Set the name for the Panic Info partition.
      strncpy((char *)(_nvramImage + freePartitionOffset + 4),
	      kIODTNVRAMPanicInfoPartitonName, 12);
      
      // Calculate the partition offset and size.
      _piPartitionOffset = freePartitionOffset + 0x10;
      _piPartitionSize = 0x800;
      if (_piPartitionSize + 0x20 > freePartitionSize)
	_piPartitionSize = freePartitionSize - 0x20;
      
      _piImage = _nvramImage + _piPartitionOffset;
      
      // Zero the new partition.
      bzero(_piImage, _piPartitionSize);
      
      // Set the partition size.
      *(UInt16 *)(_nvramImage + freePartitionOffset + 2) =
	(_piPartitionSize / 0x10) + 1;
      
      // Set the partition checksum.
      _nvramImage[freePartitionOffset + 1] =
	calculatePartitionChecksum(_nvramImage + freePartitionOffset);
      
      // Calculate the free partition offset and size.
      freePartitionOffset += _piPartitionSize + 0x10;
      freePartitionSize -= _piPartitionSize + 0x10;
      
      // Set the signature to 0x7f.
      _nvramImage[freePartitionOffset] = 0x7f;
      // Set the checksum to 0.
      _nvramImage[freePartitionOffset + 1] = 0;
      // Set the name for the free partition.
      strncpy((char *)(_nvramImage + freePartitionOffset + 4),
	      kIODTNVRAMFreePartitionName, 12);
      // Set the partition size.
      *(UInt16 *)(_nvramImage + freePartitionOffset + 2) =
	freePartitionSize / 0x10;
      // Set the partition checksum.
      _nvramImage[freePartitionOffset + 1] =
	calculatePartitionChecksum(_nvramImage + freePartitionOffset);
      
      // Set the nvram image as dirty.
      _nvramImageDirty = true;
    }
  } else {
    _piImage = _nvramImage + _piPartitionOffset;
  }
  
  _lastDeviceSync = 0;
  _freshInterval = TRUE;		// we will allow sync() even before the first 15 minutes have passed.

  initOFVariables();
}

void IODTNVRAM::sync(void)
{
  if (!_nvramImageDirty && !_ofImageDirty) return;
  
  // Don't try to sync OF Variables if the system has already paniced.
  if (!_systemPaniced) syncOFVariables();
  
  _nvramController->write(0, _nvramImage, kIODTNVRAMImageSize);
  _nvramController->sync();
  
  _nvramImageDirty = false;
}

bool IODTNVRAM::serializeProperties(OSSerialize *s) const
{
  bool                 result, hasPrivilege;
  UInt32               variablePerm;
  const OSSymbol       *key;
  OSDictionary         *dict;
  OSCollectionIterator *iter = 0;
  
  // Verify permissions.
  hasPrivilege = (kIOReturnSuccess == IOUserClient::clientHasPrivilege(current_task(), kIONVRAMPrivilege));

  dict = OSDictionary::withCapacity(1);
  if (dict == 0) return false;

  if (_ofDict == 0) {
    /* No nvram. Return an empty dictionary. */
  } else {
    /* Copy properties with client privilege. */
    iter = OSCollectionIterator::withCollection(_ofDict);
    if (iter == 0) {
      dict->release();
      return false;
    }
    while (1) {
      key = OSDynamicCast(OSSymbol, iter->getNextObject());
      if (key == 0) break;
      
      variablePerm = getOFVariablePerm(key);
      if ((hasPrivilege || (variablePerm != kOFVariablePermRootOnly)) &&
	  ( ! (variablePerm == kOFVariablePermKernelOnly && current_task() != kernel_task) )) {
	dict->setObject(key, _ofDict->getObject(key));
      }
    }
  }

  result = dict->serialize(s);
 
  dict->release();
  if (iter != 0) iter->release();
  
  return result;
}

OSObject *IODTNVRAM::getProperty(const OSSymbol *aKey) const
{
  IOReturn result;
  UInt32   variablePerm;
  
  if (_ofDict == 0) return 0;
  
  // Verify permissions.
  variablePerm = getOFVariablePerm(aKey);
  result = IOUserClient::clientHasPrivilege(current_task(), kIONVRAMPrivilege);
  if (result != kIOReturnSuccess) {
    if (variablePerm == kOFVariablePermRootOnly) return 0;
  }
  if (variablePerm == kOFVariablePermKernelOnly && current_task() != kernel_task) return 0;
  
  return _ofDict->getObject(aKey);
}

OSObject *IODTNVRAM::getProperty(const char *aKey) const
{
  const OSSymbol *keySymbol;
  OSObject *theObject = 0;
  
  keySymbol = OSSymbol::withCStringNoCopy(aKey);
  if (keySymbol != 0) {
    theObject = getProperty(keySymbol);
    keySymbol->release();
  }
  
  return theObject;
}

bool IODTNVRAM::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
  bool     result;
  UInt32   propType, propPerm;
  OSString *tmpString;
  OSObject *propObject = 0;
  
  if (_ofDict == 0) return false;
  
  // Verify permissions.
  propPerm = getOFVariablePerm(aKey);
  result = IOUserClient::clientHasPrivilege(current_task(), kIONVRAMPrivilege);
  if (result != kIOReturnSuccess) {
    if (propPerm != kOFVariablePermUserWrite) return false;
  }
  if (propPerm == kOFVariablePermKernelOnly && current_task() != kernel_task) return 0;

  // Don't allow creation of new properties on old world machines.
  if (getPlatform()->getBootROMType() == 0) {
    if (_ofDict->getObject(aKey) == 0) return false;
  }
  
  // Don't allow change of 'aapl,panic-info'.
  if (aKey->isEqualTo(kIODTNVRAMPanicInfoKey)) return false;
  
  // Make sure the object is of the correct type.
  propType = getOFVariableType(aKey);
  switch (propType) {
  case kOFVariableTypeBoolean :
    propObject = OSDynamicCast(OSBoolean, anObject);
    break;
    
  case kOFVariableTypeNumber :
    propObject = OSDynamicCast(OSNumber, anObject);
    break;
    
  case kOFVariableTypeString :
    propObject = OSDynamicCast(OSString, anObject);
    break;
    
  case kOFVariableTypeData :
    propObject = OSDynamicCast(OSData, anObject);
    if (propObject == 0) {
      tmpString = OSDynamicCast(OSString, anObject);
      if (tmpString != 0) {
	propObject = OSData::withBytes(tmpString->getCStringNoCopy(),
				       tmpString->getLength());
      }
    }
    break;
  }
  
  if (propObject == 0) return false;
  
  result = _ofDict->setObject(aKey, propObject);
  
  if (result) {
    if (getPlatform()->getBootROMType() == 0) {
      updateOWBootArgs(aKey, propObject);
    }
    
    _ofImageDirty = true;
  }
  
  return result;
}

void IODTNVRAM::removeProperty(const OSSymbol *aKey)
{
  bool     result;
  UInt32   propPerm;
  
  if (_ofDict == 0) return;
  
  // Verify permissions.
  propPerm = getOFVariablePerm(aKey);
  result = IOUserClient::clientHasPrivilege(current_task(), kIOClientPrivilegeAdministrator);
  if (result != kIOReturnSuccess) {
    if (propPerm != kOFVariablePermUserWrite) return;
  }
  if (propPerm == kOFVariablePermKernelOnly && current_task() != kernel_task) return;
  
  // Don't allow removal of properties on old world machines.
  if (getPlatform()->getBootROMType() == 0) return;
  
  // Don't allow change of 'aapl,panic-info'.
  if (aKey->isEqualTo(kIODTNVRAMPanicInfoKey)) return;
  
  // If the object exists, remove it from the dictionary.
  result = _ofDict->getObject(aKey) != 0;
  if (result) {
    _ofDict->removeObject(aKey);
    
    _ofImageDirty = true;
  }
}

IOReturn IODTNVRAM::setProperties(OSObject *properties)
{
  bool                 result = true;
  OSObject             *object;
  const OSSymbol       *key;
  const OSString       *tmpStr;
  OSDictionary         *dict;
  OSCollectionIterator *iter;
  
  dict = OSDynamicCast(OSDictionary, properties);
  if (dict == 0) return kIOReturnBadArgument;
  
  iter = OSCollectionIterator::withCollection(dict);
  if (iter == 0) return kIOReturnBadArgument;
  
  while (result) {
    key = OSDynamicCast(OSSymbol, iter->getNextObject());
    if (key == 0) break;
    
    object = dict->getObject(key);
    if (object == 0) continue;
    
    if (key->isEqualTo(kIONVRAMDeletePropertyKey)) {
		tmpStr = OSDynamicCast(OSString, object);
		if (tmpStr != 0) {
			key = OSSymbol::withString(tmpStr);
			removeProperty(key);
			key->release();
			result = true;
		} else {
			result = false;
		}
    } else if(key->isEqualTo(kIONVRAMSyncNowPropertyKey)) {
		tmpStr = OSDynamicCast(OSString, object);
		if (tmpStr != 0) {

			result = true; // We are not going to gaurantee sync, this is best effort

			if(safeToSync())
				sync();

		} else {
			result = false;
		}
	}
	else {
		result = setProperty(key, object);
    }

  }
  
  iter->release();
  
  if (result) return kIOReturnSuccess;
  else return kIOReturnError;
}

IOReturn IODTNVRAM::readXPRAM(IOByteCount offset, UInt8 *buffer,
			      IOByteCount length)
{
  if (_xpramImage == 0) return kIOReturnUnsupported;
  
  if ((buffer == 0) || (length == 0) ||
      (offset + length > kIODTNVRAMXPRAMSize))
    return kIOReturnBadArgument;
  
  bcopy(_nvramImage + _xpramPartitionOffset + offset, buffer, length);

  return kIOReturnSuccess;
}

IOReturn IODTNVRAM::writeXPRAM(IOByteCount offset, UInt8 *buffer,
			       IOByteCount length)
{
  if (_xpramImage == 0) return kIOReturnUnsupported;
  
  if ((buffer == 0) || (length == 0) ||
      (offset + length > kIODTNVRAMXPRAMSize))
    return kIOReturnBadArgument;
  
  bcopy(buffer, _nvramImage + _xpramPartitionOffset + offset, length);

  _nvramImageDirty = true;
  
  return kIOReturnSuccess;
}

IOReturn IODTNVRAM::readNVRAMProperty(IORegistryEntry *entry,
				      const OSSymbol **name,
				      OSData **value)
{
  IOReturn err;

  if (getPlatform()->getBootROMType())
    err = readNVRAMPropertyType1(entry, name, value);
  else
    err = readNVRAMPropertyType0(entry, name, value);
  
  return err;
}

IOReturn IODTNVRAM::writeNVRAMProperty(IORegistryEntry *entry,
				       const OSSymbol *name,
				       OSData *value)
{
  IOReturn err;
  
  if (getPlatform()->getBootROMType())
    err = writeNVRAMPropertyType1(entry, name, value);
  else
    err = writeNVRAMPropertyType0(entry, name, value);
  
  return err;
}

OSDictionary *IODTNVRAM::getNVRAMPartitions(void)
{
  return _nvramPartitionLengths;
}

IOReturn IODTNVRAM::readNVRAMPartition(const OSSymbol *partitionID,
				       IOByteCount offset, UInt8 *buffer,
				       IOByteCount length)
{
  OSNumber *partitionOffsetNumber, *partitionLengthNumber;
  UInt32   partitionOffset, partitionLength;
  
  partitionOffsetNumber =
    (OSNumber *)_nvramPartitionOffsets->getObject(partitionID);
  partitionLengthNumber =
    (OSNumber *)_nvramPartitionLengths->getObject(partitionID);
  
  if ((partitionOffsetNumber == 0) || (partitionLengthNumber == 0))
    return kIOReturnNotFound;
  
  partitionOffset = partitionOffsetNumber->unsigned32BitValue();
  partitionLength = partitionLengthNumber->unsigned32BitValue();
  
  if ((buffer == 0) || (length == 0) ||
      (offset + length > partitionLength))
    return kIOReturnBadArgument;
  
  bcopy(_nvramImage + partitionOffset + offset, buffer, length);
  
  return kIOReturnSuccess;
}

IOReturn IODTNVRAM::writeNVRAMPartition(const OSSymbol *partitionID,
					IOByteCount offset, UInt8 *buffer,
					IOByteCount length)
{
  OSNumber *partitionOffsetNumber, *partitionLengthNumber;
  UInt32   partitionOffset, partitionLength;
  
  partitionOffsetNumber =
    (OSNumber *)_nvramPartitionOffsets->getObject(partitionID);
  partitionLengthNumber =
    (OSNumber *)_nvramPartitionLengths->getObject(partitionID);
  
  if ((partitionOffsetNumber == 0) || (partitionLengthNumber == 0))
    return kIOReturnNotFound;
  
  partitionOffset = partitionOffsetNumber->unsigned32BitValue();
  partitionLength = partitionLengthNumber->unsigned32BitValue();
  
  if ((buffer == 0) || (length == 0) ||
      (offset + length > partitionLength))
    return kIOReturnBadArgument;
  
  bcopy(buffer, _nvramImage + partitionOffset + offset, length);
  
  _nvramImageDirty = true;
  
  return kIOReturnSuccess;
}

IOByteCount IODTNVRAM::savePanicInfo(UInt8 *buffer, IOByteCount length)
{
  if ((_piImage == 0) || (length <= 0)) return 0;
  
  if (length > (_piPartitionSize - 4))
    length = _piPartitionSize - 4;
  
  // Save the Panic Info.
  bcopy(buffer, _piImage + 4, length);
  
  // Save the Panic Info length.
  *(UInt32 *)_piImage = length;
  
  _nvramImageDirty = true;
  /* 
   * This prevents OF variables from being committed if the system has panicked
   */
  _systemPaniced = true;
  /* The call to sync() forces the NVRAM controller to write the panic info
   * partition to NVRAM.
   */
  sync();

  return length;
}

// Private methods

UInt8 IODTNVRAM::calculatePartitionChecksum(UInt8 *partitionHeader)
{
  UInt8 cnt, isum, csum = 0;
  
  for (cnt = 0; cnt < 0x10; cnt++) {
    isum = csum + partitionHeader[cnt];
    if (isum < csum) isum++;
    csum = isum;
  }
  
  return csum;
}

struct OWVariablesHeader {
  UInt16   owMagic;
  UInt8    owVersion;
  UInt8    owPages;
  UInt16   owChecksum;
  UInt16   owHere;
  UInt16   owTop;
  UInt16   owNext;
  UInt32   owFlags;
  UInt32   owNumbers[9];
  struct {
    UInt16 offset;
    UInt16 length;
  }        owStrings[10];
};
typedef struct OWVariablesHeader OWVariablesHeader;

IOReturn IODTNVRAM::initOFVariables(void)
{
  UInt32            cnt, propOffset, propType;
  UInt8             *propName, *propData;
  UInt32            propNameLength, propDataLength;
  const OSSymbol    *propSymbol;
  OSObject          *propObject;
  OWVariablesHeader *owHeader;

  if (_ofImage == 0) return kIOReturnNotReady;
  
  _ofDict =  OSDictionary::withCapacity(1);
  if (_ofDict == 0) return kIOReturnNoMemory;
  
  if (getPlatform()->getBootROMType()) {
    cnt = 0;
    while (cnt < _ofPartitionSize) {
      // Break if there is no name.
      if (_ofImage[cnt] == '\0') break;
      
      // Find the length of the name.
      propName = _ofImage + cnt;
      for (propNameLength = 0; (cnt + propNameLength) < _ofPartitionSize;
	   propNameLength++) {
	if (_ofImage[cnt + propNameLength] == '=') break;
      }
      
      // Break if the name goes past the end of the partition.
      if ((cnt + propNameLength) >= _ofPartitionSize) break;
      cnt += propNameLength + 1;
      
      propData = _ofImage + cnt;
      for (propDataLength = 0; (cnt + propDataLength) < _ofPartitionSize;
	   propDataLength++) {
	if (_ofImage[cnt + propDataLength] == '\0') break;
      }
      
      // Break if the data goes past the end of the partition.
      if ((cnt + propDataLength) >= _ofPartitionSize) break;
      cnt += propDataLength + 1;
      
      if (convertPropToObject(propName, propNameLength,
			      propData, propDataLength,
			      &propSymbol, &propObject)) {
	_ofDict->setObject(propSymbol, propObject);
	propSymbol->release();
	propObject->release();
      }
    }
    
    // Create the boot-args property if it is not in the dictionary.
    if (_ofDict->getObject("boot-args") == 0) {
      propObject = OSString::withCStringNoCopy("");
      if (propObject != 0) {
	_ofDict->setObject("boot-args", propObject);
	propObject->release();
      }
    }
    
    // Create the 'aapl,panic-info' property if needed.
    if (_piImage != 0) {
      propDataLength = *(UInt32 *)_piImage;
      if ((propDataLength != 0) && (propDataLength <= (_piPartitionSize - 4))) {
	propObject = OSData::withBytes(_piImage + 4, propDataLength);
	_ofDict->setObject(kIODTNVRAMPanicInfoKey, propObject);
	propObject->release();
	
	// Clear the length from _piImage and mark dirty.
	*(UInt32 *)_piImage = 0;
	_nvramImageDirty = true;
      }
    }
  } else {
    owHeader = (OWVariablesHeader *)_ofImage;
    if (!validateOWChecksum(_ofImage)) {
      _ofDict->release();
      _ofDict = 0;
      return kIOReturnBadMedia;
    }
    
    cnt = 0;
    while (1) {
      if (!getOWVariableInfo(cnt++, &propSymbol, &propType, &propOffset))
	break;
      
      switch (propType) {
      case kOFVariableTypeBoolean :
	propObject = OSBoolean::withBoolean(owHeader->owFlags & propOffset);
	break;
	
      case kOFVariableTypeNumber :
	propObject = OSNumber::withNumber(owHeader->owNumbers[propOffset], 32);
	break;
	
      case kOFVariableTypeString :
	propData = _ofImage + owHeader->owStrings[propOffset].offset -
	  _ofPartitionOffset;
	propDataLength = owHeader->owStrings[propOffset].length;
	propName = IONew(UInt8, propDataLength + 1);
	if (propName != 0) {
	  strncpy((char *)propName, (const char *)propData, propDataLength);
	  propName[propDataLength] = '\0';
	  propObject = OSString::withCString((const char *)propName);
	  IODelete(propName, UInt8, propDataLength + 1);
	}
	break;
      }
      
      if (propObject == 0) break;
      
      _ofDict->setObject(propSymbol, propObject);
      propSymbol->release();
      propObject->release();
    }
    
    // Create the boot-args property.
    propSymbol = OSSymbol::withCString("boot-command");
    if (propSymbol != 0) {
      propObject = _ofDict->getObject(propSymbol);
      if (propObject != 0) {
	updateOWBootArgs(propSymbol, propObject);
      }
      propSymbol->release();
    }
  }
  
  return kIOReturnSuccess;
}

IOReturn IODTNVRAM::syncOFVariables(void)
{
  bool                 ok;
  UInt32               cnt, length, maxLength;
  UInt32               curOffset, tmpOffset, tmpType, tmpDataLength;
  UInt8                *buffer, *tmpBuffer;
  const UInt8          *tmpData;
  const OSSymbol       *tmpSymbol;
  OSObject             *tmpObject;
  OSBoolean            *tmpBoolean;
  OSNumber             *tmpNumber;
  OSString             *tmpString;
  OSCollectionIterator *iter;
  OWVariablesHeader    *owHeader, *owHeaderOld;
  
  if ((_ofImage == 0) || (_ofDict == 0)) return kIOReturnNotReady;
  
  if (!_ofImageDirty) return kIOReturnSuccess;
  
  if (getPlatform()->getBootROMType()) {
    buffer = tmpBuffer = IONew(UInt8, _ofPartitionSize);
    if (buffer == 0) return kIOReturnNoMemory;
    bzero(buffer, _ofPartitionSize);
    
    ok = true;
    maxLength = _ofPartitionSize;
    
    iter = OSCollectionIterator::withCollection(_ofDict);
    if (iter == 0) ok = false;
    
    while (ok) {
      tmpSymbol = OSDynamicCast(OSSymbol, iter->getNextObject());
      if (tmpSymbol == 0) break;
      
      // Don't save 'aapl,panic-info'.
      if (tmpSymbol->isEqualTo(kIODTNVRAMPanicInfoKey)) continue;
      
      tmpObject = _ofDict->getObject(tmpSymbol);
      
      length = maxLength;
      ok = convertObjectToProp(tmpBuffer, &length, tmpSymbol, tmpObject);
      if (ok) {
	tmpBuffer += length;
	maxLength -= length;
      }
    }
    iter->release();
    
    if (ok) {
      bcopy(buffer, _ofImage, _ofPartitionSize);
    }
    
    IODelete(buffer, UInt8, _ofPartitionSize);
    
    if (!ok) return kIOReturnBadArgument;
  } else {
    buffer = IONew(UInt8, _ofPartitionSize);
    if (buffer == 0) return kIOReturnNoMemory;
    bzero(buffer, _ofPartitionSize);
    
    owHeader    = (OWVariablesHeader *)buffer;
    owHeaderOld = (OWVariablesHeader *)_ofImage;
    
    owHeader->owMagic = owHeaderOld->owMagic;
    owHeader->owVersion = owHeaderOld->owVersion;
    owHeader->owPages = owHeaderOld->owPages;
    
    curOffset = _ofPartitionSize;
    
    ok = true;
    cnt = 0;
    while (ok) {
      if (!getOWVariableInfo(cnt++, &tmpSymbol, &tmpType, &tmpOffset))
	break;
      
      tmpObject = _ofDict->getObject(tmpSymbol);
      
      switch (tmpType) {
      case kOFVariableTypeBoolean :
	tmpBoolean = OSDynamicCast(OSBoolean, tmpObject);
	if (tmpBoolean->getValue()) owHeader->owFlags |= tmpOffset;
	break;
	
      case kOFVariableTypeNumber :
	tmpNumber = OSDynamicCast(OSNumber, tmpObject);
	owHeader->owNumbers[tmpOffset] = tmpNumber->unsigned32BitValue();
        break;
	
      case kOFVariableTypeString :
	tmpString = OSDynamicCast(OSString, tmpObject);
	tmpData = (const UInt8 *)tmpString->getCStringNoCopy();
	tmpDataLength = tmpString->getLength();
	
	if ((curOffset - tmpDataLength) < sizeof(OWVariablesHeader)) {
	  ok = false;
	  break;
	}
	
	owHeader->owStrings[tmpOffset].length = tmpDataLength;
	curOffset -= tmpDataLength;
	owHeader->owStrings[tmpOffset].offset = curOffset + _ofPartitionOffset;
	if (tmpDataLength != 0)
	  bcopy(tmpData, buffer + curOffset, tmpDataLength);
	break;
      }
    }
    
    if (ok) {
      owHeader->owHere = _ofPartitionOffset + sizeof(OWVariablesHeader);
      owHeader->owTop = _ofPartitionOffset + curOffset;
      owHeader->owNext = 0;
      
      owHeader->owChecksum = 0;
      owHeader->owChecksum = ~generateOWChecksum(buffer);
      
      bcopy(buffer, _ofImage, _ofPartitionSize);
    }
    
    IODelete(buffer, UInt8, _ofPartitionSize);
    
    if (!ok) return kIOReturnBadArgument;
  }
  
  _ofImageDirty = false;
  _nvramImageDirty = true;
  
  return kIOReturnSuccess;
}

struct OFVariable {
  const char *variableName;
  UInt32     variableType;
  UInt32     variablePerm;
  SInt32     variableOffset;
};
typedef struct OFVariable OFVariable;

enum {
  kOWVariableOffsetNumber = 8,
  kOWVariableOffsetString = 17
};

OFVariable gOFVariables[] = {
  {"little-endian?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 0},
  {"real-mode?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 1},
  {"auto-boot?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 2},
  {"diag-switch?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 3},
  {"fcode-debug?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 4},
  {"oem-banner?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 5},
  {"oem-logo?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 6},
  {"use-nvramrc?", kOFVariableTypeBoolean, kOFVariablePermUserRead, 7},
  {"use-generic?", kOFVariableTypeBoolean, kOFVariablePermUserRead, -1},
  {"default-mac-address?", kOFVariableTypeBoolean, kOFVariablePermUserRead,-1},
  {"real-base", kOFVariableTypeNumber, kOFVariablePermUserRead, 8},
  {"real-size", kOFVariableTypeNumber, kOFVariablePermUserRead, 9},
  {"virt-base", kOFVariableTypeNumber, kOFVariablePermUserRead, 10},
  {"virt-size", kOFVariableTypeNumber, kOFVariablePermUserRead, 11},
  {"load-base", kOFVariableTypeNumber, kOFVariablePermUserRead, 12},
  {"pci-probe-list", kOFVariableTypeNumber, kOFVariablePermUserRead, 13},
  {"pci-probe-mask", kOFVariableTypeNumber, kOFVariablePermUserRead, -1},
  {"screen-#columns", kOFVariableTypeNumber, kOFVariablePermUserRead, 14},
  {"screen-#rows", kOFVariableTypeNumber, kOFVariablePermUserRead, 15},
  {"selftest-#megs", kOFVariableTypeNumber, kOFVariablePermUserRead, 16},
  {"boot-device", kOFVariableTypeString, kOFVariablePermUserRead, 17},
  {"boot-file", kOFVariableTypeString, kOFVariablePermUserRead, 18},
  {"boot-screen", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"console-screen", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"diag-device", kOFVariableTypeString, kOFVariablePermUserRead, 19},
  {"diag-file", kOFVariableTypeString, kOFVariablePermUserRead, 20},
  {"input-device", kOFVariableTypeString, kOFVariablePermUserRead, 21},
  {"output-device", kOFVariableTypeString, kOFVariablePermUserRead, 22},
  {"input-device-1", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"output-device-1", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"mouse-device", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"oem-banner", kOFVariableTypeString, kOFVariablePermUserRead, 23},
  {"oem-logo", kOFVariableTypeString, kOFVariablePermUserRead, 24},
  {"nvramrc", kOFVariableTypeString, kOFVariablePermUserRead, 25},
  {"boot-command", kOFVariableTypeString, kOFVariablePermUserRead, 26},
  {"default-client-ip", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"default-server-ip", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"default-gateway-ip", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"default-subnet-mask", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"default-router-ip", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"boot-script", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"boot-args", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"aapl,pci", kOFVariableTypeData, kOFVariablePermRootOnly, -1},
  {"security-mode", kOFVariableTypeString, kOFVariablePermUserRead, -1},
  {"security-password", kOFVariableTypeData, kOFVariablePermRootOnly, -1},
  {"boot-image", kOFVariableTypeData, kOFVariablePermUserWrite, -1},
  {"com.apple.System.fp-state", kOFVariableTypeData, kOFVariablePermKernelOnly, -1},
#if CONFIG_EMBEDDED
  {"backlight-level", kOFVariableTypeData, kOFVariablePermUserWrite, -1},
#endif
  {0, kOFVariableTypeData, kOFVariablePermUserRead, -1}
};

UInt32 IODTNVRAM::getOFVariableType(const OSSymbol *propSymbol) const
{
  OFVariable *ofVar;
  
  ofVar = gOFVariables;
  while (1) {
    if ((ofVar->variableName == 0) ||
	propSymbol->isEqualTo(ofVar->variableName)) break;
    ofVar++;
  }
  
  return ofVar->variableType;
}

UInt32 IODTNVRAM::getOFVariablePerm(const OSSymbol *propSymbol) const
{
  OFVariable *ofVar;
  
  ofVar = gOFVariables;
  while (1) {
    if ((ofVar->variableName == 0) ||
	propSymbol->isEqualTo(ofVar->variableName)) break;
    ofVar++;
  }
  
  return ofVar->variablePerm;
}

bool IODTNVRAM::getOWVariableInfo(UInt32 variableNumber, const OSSymbol **propSymbol,
				  UInt32 *propType, UInt32 *propOffset)
{
  OFVariable *ofVar;
  
  ofVar = gOFVariables;
  while (1) {
    if (ofVar->variableName == 0) return false;
    
    if (ofVar->variableOffset == (SInt32) variableNumber) break;
    
    ofVar++;
  }
  
  *propSymbol = OSSymbol::withCStringNoCopy(ofVar->variableName);
  *propType = ofVar->variableType;
  
  switch (*propType) {
  case kOFVariableTypeBoolean :
    *propOffset = 1 << (31 - variableNumber);
    break;
    
  case kOFVariableTypeNumber :
    *propOffset = variableNumber - kOWVariableOffsetNumber;
    break;
    
  case kOFVariableTypeString :
    *propOffset = variableNumber - kOWVariableOffsetString;
    break;
  }
  
  return true;
}

bool IODTNVRAM::convertPropToObject(UInt8 *propName, UInt32 propNameLength,
				    UInt8 *propData, UInt32 propDataLength,
				    const OSSymbol **propSymbol,
				    OSObject **propObject)
{
  UInt32         propType;
  const OSSymbol *tmpSymbol;
  OSObject       *tmpObject;
  OSNumber       *tmpNumber;
  OSString       *tmpString;
  
  // Create the symbol.
  propName[propNameLength] = '\0';
  tmpSymbol = OSSymbol::withCString((const char *)propName);
  propName[propNameLength] = '=';
  if (tmpSymbol == 0) {
    return false;
  }
  
  propType = getOFVariableType(tmpSymbol);
  
  // Create the object.
  tmpObject = 0;
  switch (propType) {
  case kOFVariableTypeBoolean :
    if (!strncmp("true", (const char *)propData, propDataLength)) {
      tmpObject = kOSBooleanTrue;
    } else if (!strncmp("false", (const char *)propData, propDataLength)) {
      tmpObject = kOSBooleanFalse;
    }
    break;
    
  case kOFVariableTypeNumber :
    tmpNumber = OSNumber::withNumber(strtol((const char *)propData, 0, 0), 32);
    if (tmpNumber != 0) tmpObject = tmpNumber;
    break;
    
  case kOFVariableTypeString :
    tmpString = OSString::withCString((const char *)propData);
    if (tmpString != 0) tmpObject = tmpString;
    break;
    
  case kOFVariableTypeData :
    tmpObject = unescapeBytesToData(propData, propDataLength);
    break;
  }
  
  if (tmpObject == 0) {
    tmpSymbol->release();
    return false;
  }
  
  *propSymbol = tmpSymbol;
  *propObject = tmpObject;
  
  return true;
}

bool IODTNVRAM::convertObjectToProp(UInt8 *buffer, UInt32 *length,
				    const OSSymbol *propSymbol, OSObject *propObject)
{
  const UInt8    *propName;
  UInt32         propNameLength, propDataLength;
  UInt32         propType, tmpValue;
  OSBoolean      *tmpBoolean = 0;
  OSNumber       *tmpNumber = 0;
  OSString       *tmpString = 0;
  OSData         *tmpData = 0;
  
  propName = (const UInt8 *)propSymbol->getCStringNoCopy();
  propNameLength = propSymbol->getLength();
  propType = getOFVariableType(propSymbol);
  
  // Get the size of the data.
  propDataLength = 0xFFFFFFFF;
  switch (propType) {
  case kOFVariableTypeBoolean :
    tmpBoolean = OSDynamicCast(OSBoolean, propObject);
    if (tmpBoolean != 0) propDataLength = 5;
    break;
    
  case kOFVariableTypeNumber :
    tmpNumber = OSDynamicCast(OSNumber, propObject);
    if (tmpNumber != 0) propDataLength = 10;
    break;
    
  case kOFVariableTypeString :
    tmpString = OSDynamicCast(OSString, propObject);
    if (tmpString != 0) propDataLength = tmpString->getLength();
    break;
    
  case kOFVariableTypeData :
    tmpData = OSDynamicCast(OSData, propObject); 
    if (tmpData != 0) {
      tmpData = escapeDataToData(tmpData);
      propDataLength = tmpData->getLength();
    }
    break;
  }
  
  // Make sure the propertySize is known and will fit.
  if (propDataLength == 0xFFFFFFFF) return false;
  if ((propNameLength + propDataLength + 2) > *length) return false;
  
  // Copy the property name equal sign.
  buffer += snprintf((char *)buffer, *length, "%s=", propName);
  
  switch (propType) {
  case kOFVariableTypeBoolean :
    if (tmpBoolean->getValue()) {
      strlcpy((char *)buffer, "true", *length - propNameLength);
    } else {
      strlcpy((char *)buffer, "false", *length - propNameLength);
    }
    break;
    
  case kOFVariableTypeNumber :
    tmpValue = tmpNumber->unsigned32BitValue();
    if (tmpValue == 0xFFFFFFFF) {
      strlcpy((char *)buffer, "-1", *length - propNameLength);
    } else if (tmpValue < 1000) {
      snprintf((char *)buffer, *length - propNameLength, "%d", (uint32_t)tmpValue);
    } else {
      snprintf((char *)buffer, *length - propNameLength, "0x%x", (uint32_t)tmpValue);
    }
    break;
    
  case kOFVariableTypeString :
    strlcpy((char *)buffer, tmpString->getCStringNoCopy(), *length - propNameLength);
    break;
    
  case kOFVariableTypeData :
    bcopy(tmpData->getBytesNoCopy(), buffer, propDataLength);
    tmpData->release();
    break;
  }
  
  propDataLength = strlen((const char *)buffer);  
  
  *length = propNameLength + propDataLength + 2;
  
  return true;
}


UInt16 IODTNVRAM::generateOWChecksum(UInt8 *buffer)
{
  UInt32 cnt, checksum = 0;
  UInt16 *tmpBuffer = (UInt16 *)buffer;
  
  for (cnt = 0; cnt < _ofPartitionSize / 2; cnt++)
    checksum += tmpBuffer[cnt];
  
  return checksum % 0x0000FFFF;
}

bool IODTNVRAM::validateOWChecksum(UInt8 *buffer)
{
  UInt32 cnt, checksum, sum = 0;
  UInt16 *tmpBuffer = (UInt16 *)buffer;
  
  for (cnt = 0; cnt < _ofPartitionSize / 2; cnt++)
    sum += tmpBuffer[cnt];
  
  checksum = (sum >> 16) + (sum & 0x0000FFFF);
  if (checksum == 0x10000) checksum--;
  checksum = (checksum ^ 0x0000FFFF) & 0x0000FFFF;
  
  return checksum == 0;
}

void IODTNVRAM::updateOWBootArgs(const OSSymbol *key, OSObject *value)
{
  bool        wasBootArgs, bootr = false;
  UInt32      cnt;
  OSString    *tmpString, *bootCommand, *bootArgs = 0;
  const UInt8 *bootCommandData, *bootArgsData;
  UInt8       *tmpData;
  UInt32      bootCommandDataLength, bootArgsDataLength, tmpDataLength;
  
  tmpString = OSDynamicCast(OSString, value);
  if (tmpString == 0) return;
  
  if (key->isEqualTo("boot-command")) {
    wasBootArgs = false;
    bootCommand = tmpString;
  } else if (key->isEqualTo("boot-args")) {
    wasBootArgs = true;
    bootArgs = tmpString;
    bootCommand = OSDynamicCast(OSString, _ofDict->getObject("boot-command"));
    if (bootCommand == 0) return;
  } else return;
  
  bootCommandData = (const UInt8 *)bootCommand->getCStringNoCopy();
  bootCommandDataLength = bootCommand->getLength();
  
  if (bootCommandData == 0) return;
  
  for (cnt = 0; cnt < bootCommandDataLength; cnt++) {
    if ((bootCommandData[cnt] == 'b') &&
	!strncmp("bootr", (const char *)bootCommandData + cnt, 5)) {
      cnt += 5;
      while (bootCommandData[cnt] == ' ') cnt++;
      bootr = true;
      break;
    }
  }
  if (!bootr) {
    _ofDict->removeObject("boot-args");
    return;
  }
  
  if (wasBootArgs) {
    bootArgsData = (const UInt8 *)bootArgs->getCStringNoCopy();
    bootArgsDataLength = bootArgs->getLength();
    if (bootArgsData == 0) return;
    
    tmpDataLength = cnt + bootArgsDataLength;
    tmpData = IONew(UInt8, tmpDataLength + 1);
    if (tmpData == 0) return;
    
    cnt -= strlcpy((char *)tmpData, (const char *)bootCommandData, cnt);
    strlcat((char *)tmpData, (const char *)bootArgsData, cnt);
    
    bootCommand = OSString::withCString((const char *)tmpData);
    if (bootCommand != 0) {
      _ofDict->setObject("boot-command", bootCommand);
      bootCommand->release();
    }
    
    IODelete(tmpData, UInt8, tmpDataLength + 1);
  } else {
    bootArgs = OSString::withCString((const char *)(bootCommandData + cnt));
    if (bootArgs != 0) {
      _ofDict->setObject("boot-args", bootArgs);
      bootArgs->release();
    }
  }
}


// Private methods for Name Registry access.

enum {
  kMaxNVNameLength = 4,
  kMaxNVDataLength = 8
};

struct NVRAMProperty
{
  IONVRAMDescriptor   header;
  UInt8               nameLength;
  UInt8               name[ kMaxNVNameLength ];
  UInt8               dataLength;
  UInt8               data[ kMaxNVDataLength ];
};

bool IODTNVRAM::searchNVRAMProperty(IONVRAMDescriptor *hdr, UInt32 *where)
{
  UInt32 offset;
  SInt32 nvEnd;
  
  nvEnd = *((UInt16 *)_nrImage);
  if(getPlatform()->getBootROMType()) {
    // on NewWorld, offset to partition start
    nvEnd -= 0x100;
  } else {
    // on old world, absolute
    nvEnd -= _nrPartitionOffset;
  }
  if((nvEnd < 0) || (nvEnd >= kIODTNVRAMNameRegistrySize))
    nvEnd = 2;
  
  offset = 2;
  while ((offset + sizeof(NVRAMProperty)) <= (UInt32)nvEnd) {
    if (bcmp(_nrImage + offset, hdr, sizeof(*hdr)) == 0) {
      *where = offset;
      return true;
    }
    offset += sizeof(NVRAMProperty);
  }
  
  if ((nvEnd + sizeof(NVRAMProperty)) <= kIODTNVRAMNameRegistrySize)
    *where = nvEnd;
  else
    *where = 0;
  
  return false;
}

IOReturn IODTNVRAM::readNVRAMPropertyType0(IORegistryEntry *entry,
					   const OSSymbol **name,
					   OSData **value)
{
  IONVRAMDescriptor hdr;
  NVRAMProperty     *prop;
  IOByteCount       length;
  UInt32            offset;
  IOReturn          err;
  char              nameBuf[kMaxNVNameLength + 1];
  
  if (_nrImage == 0) return kIOReturnUnsupported;
  if ((entry == 0) || (name == 0) || (value == 0)) return kIOReturnBadArgument;
  
  err = IODTMakeNVDescriptor(entry, &hdr);
  if (err != kIOReturnSuccess) return err;
  
  if (searchNVRAMProperty(&hdr, &offset)) {
    prop = (NVRAMProperty *)(_nrImage + offset);
    
    length = prop->nameLength;
    if (length > kMaxNVNameLength) length = kMaxNVNameLength;
    strncpy(nameBuf, (const char *)prop->name, length);
    nameBuf[length] = 0;
    *name = OSSymbol::withCString(nameBuf);
    
    length = prop->dataLength;
    if (length > kMaxNVDataLength) length = kMaxNVDataLength;
    *value = OSData::withBytes(prop->data, length);
    
    if ((*name != 0) && (*value != 0)) return kIOReturnSuccess;
    else return kIOReturnNoMemory;
  }
  
  return kIOReturnNoResources;
}

IOReturn IODTNVRAM::writeNVRAMPropertyType0(IORegistryEntry *entry,
					    const OSSymbol *name,
					    OSData *value)
{
  IONVRAMDescriptor hdr;
  NVRAMProperty     *prop;
  IOByteCount       nameLength;
  IOByteCount       dataLength;
  UInt32            offset;
  IOReturn          err;
  UInt16            nvLength;
  bool              exists;
  
  if (_nrImage == 0) return kIOReturnUnsupported;
  if ((entry == 0) || (name == 0) || (value == 0)) return kIOReturnBadArgument;
  
  nameLength = name->getLength();
  dataLength = value->getLength();
  if (nameLength > kMaxNVNameLength) return kIOReturnNoSpace;
  if (dataLength > kMaxNVDataLength) return kIOReturnNoSpace;
  
  err = IODTMakeNVDescriptor(entry, &hdr);
  if (err != kIOReturnSuccess) return err;
  
  exists = searchNVRAMProperty(&hdr, &offset);
  if (offset == 0) return kIOReturnNoMemory;
  
  prop = (NVRAMProperty *)(_nrImage + offset);
  if (!exists) bcopy(&hdr, &prop->header, sizeof(hdr));
  
  prop->nameLength = nameLength;
  bcopy(name->getCStringNoCopy(), prop->name, nameLength);
  prop->dataLength = dataLength;
  bcopy(value->getBytesNoCopy(), prop->data, dataLength);
  
  if (!exists) {
    nvLength = offset + sizeof(NVRAMProperty);
    if (getPlatform()->getBootROMType())
      nvLength += 0x100;
    else
      nvLength += _nrPartitionOffset;
    *((UInt16 *)_nrImage) = nvLength;
  }
  
  _nvramImageDirty = true;
  
  return err;
}

OSData *IODTNVRAM::unescapeBytesToData(const UInt8 *bytes, UInt32 length)
{
  OSData *data = 0;
  UInt32 totalLength = 0;
  UInt32 cnt, cnt2;
  UInt8  byte;
  bool   ok;

  // Calculate the actual length of the data.
  ok = true;
  totalLength = 0;
  for (cnt = 0; cnt < length;) {
    byte = bytes[cnt++];
    if (byte == 0xFF) {
      byte = bytes[cnt++];
      if (byte == 0x00) {
        ok = false;
        break;
      }
      cnt2 = byte & 0x7F;
    } else
      cnt2 = 1;
    totalLength += cnt2;
  }

  if (ok) {
    // Create an empty OSData of the correct size.
    data = OSData::withCapacity(totalLength);
    if (data != 0) {
      for (cnt = 0; cnt < length;) {
        byte = bytes[cnt++];
        if (byte == 0xFF) {
          byte = bytes[cnt++];
          cnt2 = byte & 0x7F;
          byte = (byte & 0x80) ? 0xFF : 0x00;
        } else
          cnt2 = 1;
        data->appendByte(byte, cnt2);
      }
    }
  }

  return data;
}

OSData * IODTNVRAM::escapeDataToData(OSData * value)
{
  OSData *       result;
  const UInt8 *  startPtr;
  const UInt8 *  endPtr;
  const UInt8 *  wherePtr;
  UInt8          byte;
  bool	         ok = true;

  wherePtr = (const UInt8 *) value->getBytesNoCopy();
  endPtr = wherePtr + value->getLength();

  result = OSData::withCapacity(endPtr - wherePtr);
  if (!result)
    return result;

  while (wherePtr < endPtr) {
    startPtr = wherePtr;
    byte = *wherePtr++;
    if ((byte == 0x00) || (byte == 0xFF)) {
      for (;
            ((wherePtr - startPtr) < 0x80) && (wherePtr < endPtr) && (byte == *wherePtr);
            wherePtr++)	{}
      ok &= result->appendByte(0xff, 1);
      byte = (byte & 0x80) | (wherePtr - startPtr);
    }
    ok &= result->appendByte(byte, 1);
  }
  ok &= result->appendByte(0, 1);

  if (!ok) {
    result->release();
    result = 0;
  }

  return result;
}

static bool IsApplePropertyName(const char * propName)
{
  char c;
  while ((c = *propName++)) {
    if ((c >= 'A') && (c <= 'Z'))
      break;
  }

  return (c == 0);
}

IOReturn IODTNVRAM::readNVRAMPropertyType1(IORegistryEntry *entry,
					   const OSSymbol **name,
					   OSData **value)
{
  IOReturn    err = kIOReturnNoResources;
  OSData      *data;
  const UInt8 *startPtr;
  const UInt8 *endPtr;
  const UInt8 *wherePtr;
  const UInt8 *nvPath = 0;
  const char  *nvName = 0;
  const char  *resultName = 0;
  const UInt8 *resultValue = 0;
  UInt32       resultValueLen = 0;
  UInt8       byte;

  if (_ofDict == 0) return err;
  data = OSDynamicCast(OSData, _ofDict->getObject(_registryPropertiesKey));
  if (data == 0) return err;
  
  startPtr = (const UInt8 *) data->getBytesNoCopy();
  endPtr = startPtr + data->getLength();

  wherePtr = startPtr;
  while (wherePtr < endPtr) {
    byte = *(wherePtr++);
    if (byte)
      continue;
    
    if (nvPath == 0)
      nvPath = startPtr;
    else if (nvName == 0)
      nvName = (const char *) startPtr;
    else {
      IORegistryEntry * compareEntry = IORegistryEntry::fromPath((const char *) nvPath, gIODTPlane);
      if (compareEntry)
        compareEntry->release();
      if (entry == compareEntry) {
        bool appleProp = IsApplePropertyName(nvName);
        if (!appleProp || !resultName) {
          resultName     = nvName;
          resultValue    = startPtr;
          resultValueLen = wherePtr - startPtr - 1;
        }
        if (!appleProp)
          break;
      }
      nvPath = 0;
      nvName = 0;
    }
    startPtr = wherePtr;
  }
  if (resultName) {
    *name = OSSymbol::withCString(resultName);
    *value = unescapeBytesToData(resultValue, resultValueLen);
    if ((*name != 0) && (*value != 0))
      err = kIOReturnSuccess;
    else
      err = kIOReturnNoMemory;
  }
  return err;
}

IOReturn IODTNVRAM::writeNVRAMPropertyType1(IORegistryEntry *entry,
					    const OSSymbol *propName,
					    OSData *value)
{
  OSData       *oldData;
  OSData       *data = 0;
  const UInt8  *startPtr;
  const UInt8  *propStart;
  const UInt8  *endPtr;
  const UInt8  *wherePtr;
  const UInt8  *nvPath = 0;
  const char   *nvName = 0;
  const char * comp;
  const char * name;
  UInt8        byte;
  bool         ok = true;
  bool         settingAppleProp;

  if (_ofDict == 0) return kIOReturnNoResources;

  settingAppleProp = IsApplePropertyName(propName->getCStringNoCopy());

  // copy over existing properties for other entries

  oldData = OSDynamicCast(OSData, _ofDict->getObject(_registryPropertiesKey));
  if (oldData) {
    startPtr = (const UInt8 *) oldData->getBytesNoCopy();
    endPtr = startPtr + oldData->getLength();
    
    propStart = startPtr;
    wherePtr = startPtr;
    while (wherePtr < endPtr) {
      byte = *(wherePtr++);
      if (byte)
        continue;
      if (nvPath == 0)
        nvPath = startPtr;
      else if (nvName == 0)
        nvName = (const char *) startPtr;
      else {
        IORegistryEntry * compareEntry = IORegistryEntry::fromPath((const char *) nvPath, gIODTPlane);
        if (compareEntry)
          compareEntry->release();
        if (entry == compareEntry) {
          if ((settingAppleProp && propName->isEqualTo(nvName))
           || (!settingAppleProp && !IsApplePropertyName(nvName))) {
             // delete old property (nvPath -> wherePtr)
             data = OSData::withBytes(propStart, nvPath - propStart);
             if (data)
               ok &= data->appendBytes(wherePtr, endPtr - wherePtr);
             break;
          }
        }
        nvPath = 0;
        nvName = 0;
      }
        
      startPtr = wherePtr;
    }
  }

  // make the new property

  if (!data) {
    if (oldData)
      data = OSData::withData(oldData);
    else
      data = OSData::withCapacity(16);
    if (!data)
      return kIOReturnNoMemory;
  }

  if (value && value->getLength()) {
		// get entries in path
		OSArray *array = OSArray::withCapacity(5);
		if (!array) {
			data->release();
			return kIOReturnNoMemory;
		}
		do
			array->setObject(entry);
		while ((entry = entry->getParentEntry(gIODTPlane)));

		// append path
		for (int i = array->getCount() - 3;
					(entry = (IORegistryEntry *) array->getObject(i));
					i--) {

			name = entry->getName(gIODTPlane);
			comp = entry->getLocation(gIODTPlane);
			if( comp && (0 == strncmp("pci", name, sizeof("pci")))
			 && (0 == strncmp("80000000", comp, sizeof("80000000")))) {
				// yosemite hack
				comp = "/pci@80000000";
			} else {
				if (comp)
					ok &= data->appendBytes("/@", 2);
				else {
					if (!name)
						continue;
					ok &= data->appendByte('/', 1);
					comp = name;
				}
			}
			ok &= data->appendBytes(comp, strlen(comp));
		}
		ok &= data->appendByte(0, 1);
		array->release();

		// append prop name
		ok &= data->appendBytes(propName->getCStringNoCopy(), propName->getLength() + 1);
		
		// append escaped data
		oldData = escapeDataToData(value);
		ok &= (oldData != 0);
		if (ok)
			ok &= data->appendBytes(oldData);
	}
  if (ok) {
    ok = _ofDict->setObject(_registryPropertiesKey, data);
    if (ok)
      _ofImageDirty = true;
  }
  data->release();

  return ok ? kIOReturnSuccess : kIOReturnNoMemory;
}

bool IODTNVRAM::safeToSync(void)
{
    AbsoluteTime delta;
    UInt64       delta_ns;
    SInt32       delta_secs;
	
	// delta interval went by
	clock_get_uptime(&delta);
	
    // Figure it in seconds.
    absolutetime_to_nanoseconds(delta, &delta_ns);
    delta_secs = (SInt32)(delta_ns / NSEC_PER_SEC);

	if ((delta_secs > (_lastDeviceSync + MIN_SYNC_NOW_INTERVAL)) || _freshInterval)
	{
		_lastDeviceSync = delta_secs;
		_freshInterval = FALSE;
		return TRUE;
	}

	return FALSE;
}
