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

#include <IOKit/nvram/IONVRAMController.h>

enum {
  kNVRAMTypeNone = 0,
  kNVRAMTypeIOMem,
  kNVRAMTypePort,
  
  kNVRAMImageSize = 0x2000
};

class AppleNVRAM : public IONVRAMController
{
  OSDeclareDefaultStructors(AppleNVRAM);
  
private:
  UInt32         _nvramType;
  volatile UInt8 *_nvramData;
  volatile UInt8 *_nvramPort;
  
public:
  bool start(IOService *provider);
  
  virtual IOReturn read(IOByteCount offset, UInt8 *buffer,
			IOByteCount length);
  virtual IOReturn write(IOByteCount offset, UInt8 *buffer,
			 IOByteCount length);
};
