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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *
 */

#include <IOKit/IODeviceTreeSupport.h>

#include "PowerExpress.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super ApplePlatformExpert

OSDefineMetaClassAndStructors(PowerExpressPE, ApplePlatformExpert);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool PowerExpressPE::start(IOService *provider)
{
  OSData *tmpData;
  
  setChipSetType(kChipSetTypePowerExpress);
  
  tmpData = OSDynamicCast(OSData, getProperty("senses"));
  if (tmpData) senseArray = (long *)tmpData->getBytesNoCopy();
  
  return super::start(provider);
}

bool PowerExpressPE::platformAdjustService(IOService *service)
{
  long     cnt, numInterrupts, sourceNumbers[2];
  OSData   *tmpData;
  OSArray  *controllers, *specifiers;
  OSSymbol *controller;
  
  // Fix up the interrupt data.
  controllers = OSDynamicCast(OSArray, service->getProperty(gIOInterruptControllersKey));
  specifiers = OSDynamicCast(OSArray, service->getProperty(gIOInterruptSpecifiersKey));
  if (controllers && specifiers) {
    numInterrupts = specifiers->getCount();
    for (cnt = 0; cnt < numInterrupts; cnt++) {
      // Only change interrupts for MPIC.
      controller = OSDynamicCast(OSSymbol, controllers->getObject(cnt));
      if (controller == gIODTDefaultInterruptController) {
	tmpData = OSDynamicCast(OSData, specifiers->getObject(cnt));
	if (tmpData && (tmpData->getLength() == 4)) {
	  sourceNumbers[0] = *(long *)tmpData->getBytesNoCopy();
	  sourceNumbers[1] = senseArray[sourceNumbers[0]];
	  tmpData = OSData::withBytes(sourceNumbers, 2 * sizeof(long));
	  if (tmpData) {
	    specifiers->setObject(cnt, tmpData);
	    tmpData->release();
	  }
	}
      }
    }
  }
  
  if (IODTMatchNubWithKeys(service, "open-pic")) {
    service->setProperty("InterruptControllerName",
			 gIODTDefaultInterruptController);
    return true;
  }
  
  return true;
}
