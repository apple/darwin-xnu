/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <IOKit/pwr_mgt/IOPMPowerSource.h>

#define super OSObject

OSDefineMetaClassAndStructors(IOPMPowerSource, OSObject)

// **********************************************************************************
// init
//
// **********************************************************************************
bool IOPMPowerSource::init (unsigned short whichBatteryIndex)
{
  if (!super::init ())
    return false;

  bBatteryIndex = whichBatteryIndex;
  nextInList    = 0;

  return true;
}

// **********************************************************************************
// capacityPercentRemaining
//
// **********************************************************************************
unsigned long IOPMPowerSource::capacityPercentRemaining (void)
{
   unsigned long percentage = 0;

   if (bMaxCapacity > 0)
     percentage = (bCurCapacity * 100) / bMaxCapacity;
 
   // always return a non-zero value unless the real capacity IS zero.
   if (percentage == 0 && bCurCapacity > 0)
     percentage = 1;

   return percentage;
}

// **********************************************************************************
// atWarnLevel
//
// **********************************************************************************
bool IOPMPowerSource::atWarnLevel (void)
{
  return bFlags & kBatteryAtWarn;
}

// **********************************************************************************
// acConnected
//
// **********************************************************************************
bool IOPMPowerSource::acConnected (void)
{
  return bFlags & kACInstalled;
}

// **********************************************************************************
// depleted
//
// **********************************************************************************
bool IOPMPowerSource::depleted (void)
{
  return bFlags & kBatteryDepleted;
}

// **********************************************************************************
// isInstalled
//
// **********************************************************************************
bool IOPMPowerSource::isInstalled (void)
{
  return bFlags & kBatteryInstalled;
}

// **********************************************************************************
// isCharging
//
// **********************************************************************************
bool IOPMPowerSource::isCharging (void)
{
  return bFlags & kBatteryCharging;
}

// **********************************************************************************
// timeRemaining
//
// **********************************************************************************
unsigned long IOPMPowerSource::timeRemaining (void)
{
  return bTimeRemaining;
}

// **********************************************************************************
// maxCapacity
//
// **********************************************************************************
unsigned long IOPMPowerSource::maxCapacity (void)
{
  return bMaxCapacity;
}

// **********************************************************************************
// curCapacity
//
// **********************************************************************************
unsigned long IOPMPowerSource::curCapacity (void)
{
  return bCurCapacity;
}

// **********************************************************************************
// currentDrawn
//
// **********************************************************************************
long IOPMPowerSource::currentDrawn (void)
{
  return bCurrent;
}

// **********************************************************************************
// voltage
//
// **********************************************************************************

unsigned long IOPMPowerSource::voltage (void)
{
  return bVoltage;
}

// **********************************************************************************
// updateStatus
//
// **********************************************************************************

void IOPMPowerSource::updateStatus (void)
{

}





