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

#include "PowerStar.h"
#include "../drvAppleOHare/OHare.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super ApplePlatformExpert

OSDefineMetaClassAndStructors(PowerStarPE, ApplePlatformExpert);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool PowerStarPE::start(IOService *provider)
{
  setChipSetType(kChipSetTypePowerStar);
  
  // See if it is a Hooper or Kanga.
  if (IODTMatchNubWithKeys(provider, "('AAPL,3400/2400', 'AAPL,3500')")) {
    configureEthernet(provider);
  }

  _pePMFeatures     = kStdPowerBookPMFeatures;
  _pePrivPMFeatures = kStdPowerBookPrivPMFeatures;
  _peNumBatteriesSupported = kStdPowerBookNumBatteries;
  
  return super::start(provider);
}

bool PowerStarPE::platformAdjustService(IOService *service)
{
  if (!strcmp(service->getName(), "chips65550")) {
    service->setProperty("Ignore VBL", "", 0);
    return true;
  }
  
  return true;
}

void PowerStarPE::configureEthernet(IOService *provider)
{
  OSCollectionIterator *nodeList;
  IORegistryEntry      *node, *enet, *ohare;
  OSArray              *interruptNames, *interruptSources;
  OSSymbol             *interruptControllerName;
  OSData               *tempData;
  long                 tempSource;
  
  enet = 0;
  ohare = 0;
  
  // Find the node for DEC21041.
  nodeList = IODTFindMatchingEntries(provider, kIODTRecursive,
				     "'pci1011,14'");
  if (nodeList) {
    while ((node = (IORegistryEntry *)nodeList->getNextObject())) {
      enet = node;
    }
    nodeList->release();
  }
  
  if (enet == 0) return;
  
  // Set the 'Network Connection' property to '10BaseT'.
  enet->setProperty("Network Connection", "10BaseT");
  
  // Add a 'built-in' property so IONetworkStack will treat it as built in.
  enet->setProperty("built-in", "", 0);
  
  // If it is there, find the node for the second ohare.
  nodeList = IODTFindMatchingEntries(provider, kIODTRecursive,
				     "'pci106b,7'");
  if (nodeList) {
    while ((node = (IORegistryEntry *)nodeList->getNextObject())) {
      ohare = node;
    }
    nodeList->release();
  }
  
  if (ohare == 0) return;
  
  interruptNames = OSDynamicCast(OSArray,
				 enet->getProperty(gIOInterruptControllersKey));
  interruptControllerName = (OSSymbol *)OSSymbol::withCStringNoCopy("SecondaryInterruptController");
  interruptNames->setObject(0, interruptControllerName);
  interruptControllerName->release();
  
  interruptSources = OSDynamicCast(OSArray,
				enet->getProperty(gIOInterruptSpecifiersKey));
  tempSource = 28;
  tempData = OSData::withBytes(&tempSource, sizeof(tempSource));
  interruptSources->setObject(0, tempData);
  tempData->release();
}
