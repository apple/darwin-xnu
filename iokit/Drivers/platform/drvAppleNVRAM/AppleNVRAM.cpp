/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#include <IOKit/IOLib.h>
#include "AppleNVRAM.h"


#define super IONVRAMController
OSDefineMetaClassAndStructors(AppleNVRAM, IONVRAMController);


// ****************************************************************************
// start
//
// ****************************************************************************
bool AppleNVRAM::start(IOService *provider)
{
  IOItemCount numRanges;
  IOMemoryMap *map;
  
  numRanges = provider->getDeviceMemoryCount();
  
  if (numRanges == 1) {
    _nvramType = kNVRAMTypeIOMem;
    
    // Get the address of the data register.
    map = provider->mapDeviceMemoryWithIndex(0);
    if (map == 0) return false;
    _nvramData = (UInt8 *)map->getVirtualAddress();
    
  } else if (numRanges == 2) {
    _nvramType = kNVRAMTypePort;
    
    // Get the address of the port register.
    map = provider->mapDeviceMemoryWithIndex(0);
    if (map == 0) return false;
    _nvramPort = (UInt8 *)map->getVirtualAddress();
    
    // Get the address of the data register.
    map = provider->mapDeviceMemoryWithIndex(1);
    if (map == 0) return false;
    _nvramData = (UInt8 *)map->getVirtualAddress();
    
  } else {
    return false;
  }
  
  return super::start(provider);
}

// ****************************************************************************
// read
//
// Read data from the NVRAM and return it in buffer.
//
// ****************************************************************************
IOReturn AppleNVRAM::read(IOByteCount offset, UInt8 *buffer,
			  IOByteCount length)
{
  UInt32 cnt;
  
  if ((buffer == 0) || (length <= 0) || (offset < 0) ||
      (offset + length > kNVRAMImageSize))
    return kIOReturnBadArgument;
  
  switch (_nvramType) {
  case kNVRAMTypeIOMem :
    for (cnt = 0; cnt < length; cnt++) {
      buffer[cnt] = _nvramData[(offset + cnt)  << 4];
    }
    break;
    
  case kNVRAMTypePort:
    for (cnt = 0; cnt < length; cnt++) {
      *_nvramPort = (offset + length) >> 5;
      eieio();
      buffer[cnt] = _nvramData[((offset + length) & 0x1F) << 4];
    }
    break;
    
  default :
    return kIOReturnNotReady;
  }
  
  return kIOReturnSuccess;
}


// ****************************************************************************
// write
//
// Write data from buffer into NVRAM.
//
// ****************************************************************************
IOReturn AppleNVRAM::write(IOByteCount offset, UInt8 *buffer,
			   IOByteCount length)
{
  UInt32 cnt;
  
  if ((buffer == 0) || (length <= 0) || (offset < 0) ||
      (offset + length > kNVRAMImageSize))
    return kIOReturnBadArgument;
  
  switch (_nvramType) {
  case kNVRAMTypeIOMem :
    for (cnt = 0; cnt < length; cnt++) {
      _nvramData[(offset + cnt)  << 4] = buffer[cnt];
      eieio();
    }
    break;
    
  case kNVRAMTypePort:
    for (cnt = 0; cnt < length; cnt++) {
      *_nvramPort = (offset + length) >> 5;
      eieio();
      _nvramData[((offset + length) & 0x1F) << 4] = buffer[cnt];
      eieio();
    }
    break;
    
  default :
    return kIOReturnNotReady;
  }
  
  return kIOReturnSuccess;
}
