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
 * Copyright (c) 1998-9 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *
 */

#ifndef _IOKIT_APPLENMI_H
#define _IOKIT_APPLENMI_H

#include <IOKit/IOService.h>
#include <IOKit/IOInterrupts.h>

// NMI Interrupt Constants
enum
{
    kExtInt9_NMIIntSource      = 0x800506E0,
    kNMIIntLevelMask           = 0x00004000,
    kNMIIntMask                = 0x00000080
};


class AppleNMI : public IOService
{
  OSDeclareDefaultStructors(AppleNMI);

private:
  bool enable_debugger;
  bool mask_NMI;

  struct ExpansionData { };
  ExpansionData * reserved;	// Reserved for future use

public:
  IOService *rootDomain;
  virtual bool start(IOService *provider);
  virtual IOReturn initNMI(IOInterruptController *parentController, OSData *parentSource);
  virtual IOReturn handleInterrupt(void *refCon, IOService *nub, int source);

  // Power handling methods:
  virtual IOReturn powerStateWillChangeTo(IOPMPowerFlags, unsigned long, IOService*);

  OSMetaClassDeclareReservedUnused(AppleNMI,  0);
  OSMetaClassDeclareReservedUnused(AppleNMI,  1);
  OSMetaClassDeclareReservedUnused(AppleNMI,  2);
  OSMetaClassDeclareReservedUnused(AppleNMI,  3);
};

#endif /* ! _IOKIT_APPLENMI_H */
