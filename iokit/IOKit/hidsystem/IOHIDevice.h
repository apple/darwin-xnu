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
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * IOHIDevice.h - Common Event Source object class.
 *
 * HISTORY
 * 22 May 1992    Mike Paquette at NeXT
 *      Created. 
 * 4  Aug 1993	  Erik Kay at NeXT
 *	API cleanup
 * 5  Aug 1993	  Erik Kay at NeXT
 *	added ivar space for future expansion
 */

#ifndef _IOHIDEVICE_H
#define _IOHIDEVICE_H

#include <IOKit/IOService.h>
#include <IOKit/IOLocks.h>

typedef enum {
  kHIUnknownDevice          = 0,
  kHIKeyboardDevice         = 1,
  kHIRelativePointingDevice = 2
} IOHIDKind;

class IOHIDevice : public IOService
{
  OSDeclareDefaultStructors(IOHIDevice);

public:
  virtual bool init(OSDictionary * properties = 0);
  virtual void free();

  virtual UInt32    deviceType();
  virtual IOHIDKind hidKind();
  virtual UInt32    interfaceID();
  virtual bool 	    updateProperties(void);
  virtual IOReturn  setParamProperties(OSDictionary * dict);
  virtual UInt64    getGUID();
};

#endif /* !_IOHIDEVICE_H */
