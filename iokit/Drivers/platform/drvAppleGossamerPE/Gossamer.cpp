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

extern "C" {
#include <machine/machine_routines.h>
}

#include <IOKit/pwr_mgt/RootDomain.h>

#include <IOKit/IODeviceTreeSupport.h>
//#include <IOKit/ata/IOATAStandardInterface.h>

#include "Gossamer.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super ApplePlatformExpert

OSDefineMetaClassAndStructors(GossamerPE, ApplePlatformExpert);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool GossamerPE::start(IOService *provider)
{
  unsigned int    tmpVal;
  long            machineType;
  long            allInOne;
  
  setChipSetType(kChipSetTypeGossamer);
  
  // Set the machine type.
  if (IODTMatchNubWithKeys(provider, "'AAPL,Gossamer'"))
    machineType = kGossamerTypeGossamer;
  else if (IODTMatchNubWithKeys(provider, "'AAPL,PowerMac G3'"))
    machineType = kGossamerTypeSilk;
  else if (IODTMatchNubWithKeys(provider, "'AAPL,PowerBook1998'"))
    machineType = kGossamerTypeWallstreet;
  else if (IODTMatchNubWithKeys(provider, "'iMac,1'"))
    machineType = kGossamerTypeiMac;
  else if (IODTMatchNubWithKeys(provider, "('PowerMac1,1', 'PowerMac1,2')"))
    machineType = kGossamerTypeYosemite;
  else if (IODTMatchNubWithKeys(provider, "'PowerBook1,1'"))
    machineType = kGossamerType101;
  else return false;
  
  setMachineType(machineType);
  
  // Find out if this an all in one.
  allInOne = 0;
  if (ml_probe_read(kGossamerMachineIDReg, &tmpVal)) {
    switch (getMachineType()) {
    case kGossamerTypeGossamer :
    case kGossamerTypeSilk :
      if (!(tmpVal & kGossamerAllInOneMask)) allInOne = 1;
      break;
      
    case kGossamerTypeiMac :
      allInOne = 1;
      break;
    }
  }
  if (allInOne) setProperty("AllInOne", this);
  
  // setup default power mgr features per machine
  // NOTE: on Core99 and later hardware, this information
  // is available from the "prim-info" property in the power-mgt
  // node of the device tree. Prior to that, this information
  // was just another hard-coded part of the ROM.

  switch (getMachineType()) {
  case kGossamerTypeGossamer:
  case kGossamerTypeSilk:
  case kGossamerTypeiMac:
  case kGossamerTypeYosemite:
      _pePMFeatures     = kStdDesktopPMFeatures;
      _pePrivPMFeatures = kStdDesktopPrivPMFeatures;      
      _peNumBatteriesSupported = kStdDesktopNumBatteries;
      break;

  case kGossamerTypeWallstreet:
      _pePMFeatures     = kWallstreetPMFeatures;
      _pePrivPMFeatures = kWallstreetPrivPMFeatures;
      _peNumBatteriesSupported = kStdPowerBookNumBatteries;
      break;

  case kGossamerType101:
      _pePMFeatures     = k101PMFeatures;
      _pePrivPMFeatures = k101PrivPMFeatures;
      _peNumBatteriesSupported = kStdPowerBookNumBatteries;
      break;
  }
  
  return super::start(provider);
}


bool GossamerPE::platformAdjustService(IOService *service)
{
  long            tmpNum;
  OSData          *tmpData;
  
  // Add the extra sound properties for Gossamer AIO
  if (getProperty("AllInOne") &&
      ((getMachineType() == kGossamerTypeGossamer) ||
       (getMachineType() == kGossamerTypeSilk))) {
    if (!strcmp(service->getName(), "sound")) {
      tmpNum = 3;
      tmpData = OSData::withBytes(&tmpNum, sizeof(tmpNum));
      if (tmpData) {
	service->setProperty("#-detects", tmpData);
	service->setProperty("#-outputs", tmpData);
	tmpData->release();
      }
      return true;
    }
  }
  
  // Set the loop snoop property for Wallstreet or Mainstreet.
  if (getMachineType() == kGossamerTypeWallstreet) {
    if (IODTMatchNubWithKeys(service, "('grackle', 'MOT,PPC106')")) {
      // Add the property for set loop snoop.
      service->setProperty("set-loop-snoop", service);
      return true;
    }
  }

  return true;
}

IOReturn GossamerPE::callPlatformFunction(const OSSymbol *functionName,
					  bool waitForFunction,
					  void *param1, void *param2,
					  void *param3, void *param4)
{
  if (functionName == gGetDefaultBusSpeedsKey) {
    getDefaultBusSpeeds((long *)param1, (unsigned long **)param2);
    return kIOReturnSuccess;
  }
  
  return super::callPlatformFunction(functionName, waitForFunction,
				     param1, param2, param3, param4);
}

static unsigned long gossamerSpeed[] = { 66820000, 1 };
static unsigned long yosemiteSpeed[] = { 99730000, 1 };

void GossamerPE::getDefaultBusSpeeds(long *numSpeeds,
				     unsigned long **speedList)
{
  if ((numSpeeds == 0) || (speedList == 0)) return;
  
  switch (getMachineType()) {
  case kGossamerTypeGossamer :
  case kGossamerTypeSilk :
    *numSpeeds = 1;
    *speedList = gossamerSpeed;
    break;
    
  case kGossamerTypeYosemite :
    *numSpeeds = 1;
    *speedList = yosemiteSpeed;
    break;
    
  default :
    *numSpeeds = 0;
    *speedList = 0;
    break;
  }
}


//*********************************************************************************
// PMInstantiatePowerDomains
//
// This overrides the vanilla implementation in IOPlatformExpert.  It instantiates
// a root domain with two children, one for the USB bus (to handle the USB idle
// power budget), and one for the expansions slots on the PCI bus (to handle
// the idle PCI power budget)
//*********************************************************************************

void GossamerPE::PMInstantiatePowerDomains ( void )
{
   root = new IOPMrootDomain;
   root->init();
   root->attach(this);
   root->start(this);
   root->youAreRoot();
   
/*  All G3s support sleep (or pseudo-sleep) now
   if ((getMachineType() == kGossamerType101) ||
       (getMachineType() == kGossamerTypeWallstreet))
*/
     root->setSleepSupported(kRootDomainSleepSupported);
}


//*********************************************************************************
// PMRegisterDevice
//
// This overrides the vanilla implementation in IOPlatformExpert.
//*********************************************************************************

//#define DONOTREGISTERATACONTROLLER 1

void GossamerPE::PMRegisterDevice(IOService * theNub, IOService * theDevice)
{
//#ifdef DONOTREGISTERATACONTROLLER
    // do not add IOATAStandardDriver to the tree since on this platform they do not need resets
//    if (OSDynamicCast(IOATAStandardDriver, theDevice) != NULL)
//        return;
//#endif
    
    // Checks if the nub handles power states, if it does not gets its parent and so
    // up until we reach the root, or we do not find anything:
    while ((theNub != NULL) && ( theNub->addPowerChild(theDevice) != IOPMNoErr )) {
        theNub = theNub->getProvider();

//#ifdef DONOTREGISTERATACONTROLLER
        // IOATAStandardDriver are detached, and so would be evrething I attach to them so
        // their childs go directly on the tree.
//        if (OSDynamicCast(IOATAStandardDriver, theNub) != NULL) {
//            theNub = theNub->getProvider();
//        }
//#endif
    }

    if ( theNub == NULL ) {
        root->addPowerChild ( theDevice );
        return;
    }
}
