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


#include <ppc/proc_reg.h>

#include <IOKit/IOLib.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOPlatformExpert.h>

#include <IOKit/platform/AppleNMI.h>

#include "OHare.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super AppleMacIO

OSDefineMetaClassAndStructors(OHare, AppleMacIO);

bool OHare::start(IOService *provider)
{
  IOInterruptAction  handler;
  OSSymbol           *interruptControllerName;
  AppleNMI           *appleNMI;
  long               nmiSource;
  OSData             *nmiData;
  IOReturn           error;
  
  // Call MacIO's start.
  if (!super::start(provider))
    return false;
  
  // Figure out which ohare this is.
  if (IODTMatchNubWithKeys(provider, "ohare"))
    ohareNum = kPrimaryOHare;
  else if (IODTMatchNubWithKeys(provider, "'pci106b,7'"))
    ohareNum = kSecondaryOHare;
  else return false;  // This should not happen.
  
  if (ohareNum == kPrimaryOHare) {
    getPlatform()->setCPUInterruptProperties(provider);
  }
  
  // Make nubs for the children.
  publishBelow( provider );
  
  // get the base address of the this OHare.
  ohareBaseAddress = fMemory->getVirtualAddress();
  
  // get the name of the interrupt controller
  interruptControllerName  = getInterruptControllerName();
  
  // Allocate the interruptController instance.
  interruptController = new OHareInterruptController;
  if (interruptController == NULL) return false;
  
  // call the interruptController's init method.
  error = interruptController->initInterruptController(provider, ohareBaseAddress);
  if (error != kIOReturnSuccess) return false;
  
  handler = interruptController->getInterruptHandlerAddress();
  provider->registerInterrupt(0, interruptController, handler, 0);
  
  provider->enableInterrupt(0);
  
  // Register the interrupt controller so clients can find it.
  getPlatform()->registerInterruptController(interruptControllerName,
					     interruptController);
  
  if (ohareNum != kPrimaryOHare) return true;
  
  // Create the NMI Driver.
  nmiSource = 20;
  nmiData = OSData::withBytes(&nmiSource, sizeof(long));
  appleNMI = new AppleNMI;
  if ((nmiData != 0) && (appleNMI != 0)) {
    appleNMI->initNMI(interruptController, nmiData);
  } 
  
  return true;
}

OSSymbol *OHare::getInterruptControllerName(void)
{
  OSSymbol *interruptControllerName;
  
  switch (ohareNum) {
  case kPrimaryOHare :
    interruptControllerName = gIODTDefaultInterruptController;
    break;
    
  case kSecondaryOHare :
    interruptControllerName = OSSymbol::withCStringNoCopy("SecondaryInterruptController");
    break;
    
  default:
    interruptControllerName = OSSymbol::withCStringNoCopy("UnknownInterruptController");
    break;
  }
  
  return interruptControllerName;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef  super
#define super IOInterruptController

OSDefineMetaClassAndStructors(OHareInterruptController, IOInterruptController);

IOReturn OHareInterruptController::initInterruptController(IOService *provider, IOLogicalAddress interruptControllerBase)
{
  int cnt;
  
  parentNub = provider;
  
  // Allocate the task lock.
  taskLock = IOLockAlloc();
  if (taskLock == 0) return kIOReturnNoResources;
  
  // Allocate the memory for the vectors
  vectors = (IOInterruptVector *)IOMalloc(kNumVectors * sizeof(IOInterruptVector));
  if (vectors == NULL) {
    IOLockFree(taskLock);
    return kIOReturnNoMemory;
  }
  bzero(vectors, kNumVectors * sizeof(IOInterruptVector));
  
  // Allocate locks for the 
  for (cnt = 0; cnt < kNumVectors; cnt++) {
    vectors[cnt].interruptLock = IOLockAlloc();
    if (vectors[cnt].interruptLock == NULL) {
      for (cnt = 0; cnt < kNumVectors; cnt++) {
	IOLockFree(taskLock);
	if (vectors[cnt].interruptLock != NULL)
	  IOLockFree(vectors[cnt].interruptLock);
      }
      return kIOReturnNoResources;
    }
  }
  
  // Setup the registers accessors
  eventsReg = (unsigned long)(interruptControllerBase + kEventsOffset);
  maskReg   = (unsigned long)(interruptControllerBase + kMaskOffset);
  clearReg  = (unsigned long)(interruptControllerBase + kClearOffset);
  levelsReg = (unsigned long)(interruptControllerBase + kLevelsOffset);
  
  // Initialize the registers.
  
  // Disable all interrupts.
  stwbrx(0x00000000, maskReg);
  eieio();
  
  // Clear all pending interrupts.
  stwbrx(0xFFFFFFFF, clearReg);
  eieio();
  
  // Disable all interrupts. (again?)
  stwbrx(0x00000000, maskReg);
  eieio();
  
  return kIOReturnSuccess;
}

IOInterruptAction OHareInterruptController::getInterruptHandlerAddress(void)
{
  return (IOInterruptAction)&OHareInterruptController::handleInterrupt;
}

IOReturn OHareInterruptController::handleInterrupt(void * /*refCon*/,
						   IOService * /*nub*/,
						   int /*source*/)
{
  int               done;
  long              events, vectorNumber;
  IOInterruptVector *vector;
  unsigned long     maskTmp;

  do {
    done = 1;
    
    // Do all the sources for events, plus any pending interrupts.
    // Also add in the "level" sensitive sources
    maskTmp = lwbrx(maskReg);
    events = lwbrx(eventsReg) & ~kTypeLevelMask;
    events |= lwbrx(levelsReg) & maskTmp & kTypeLevelMask;
    events |= pendingEvents & maskTmp;
    pendingEvents = 0;
    eieio();

    // Since we have to clear the level'd one clear the current edge's too.
    stwbrx(kTypeLevelMask | events, clearReg);
    eieio();
    
    if (events) done = 0;
    
    while (events) {
      vectorNumber = 31 - cntlzw(events);
      events ^= (1 << vectorNumber);
      vector = &vectors[vectorNumber];
      
      vector->interruptActive = 1;
      sync();
      isync();
      if (!vector->interruptDisabledSoft) {
	isync();
	
	// Call the handler if it exists.
	if (vector->interruptRegistered) {
	  vector->handler(vector->target, vector->refCon,
			  vector->nub, vector->source);
	}
      } else {
	// Hard disable the source.
	vector->interruptDisabledHard = 1;
	disableVectorHard(vectorNumber, vector);
      }
      
      vector->interruptActive = 0;
    }
  } while (!done);
  
  return kIOReturnSuccess;
}

bool OHareInterruptController::vectorCanBeShared(long /*vectorNumber*/, IOInterruptVector */*vector*/)
{
  return true;
}

int OHareInterruptController::getVectorType(long vectorNumber, IOInterruptVector */*vector*/)
{
  int interruptType;
  
  if (kTypeLevelMask & (1 << vectorNumber)) {
    interruptType = kIOInterruptTypeLevel;
  } else {
    interruptType = kIOInterruptTypeEdge;
  }
  
  return interruptType;
}

void OHareInterruptController::disableVectorHard(long vectorNumber, IOInterruptVector */*vector*/)
{
  unsigned long     maskTmp;
  
  // Turn the source off at hardware.
  maskTmp = lwbrx(maskReg);
  maskTmp &= ~(1 << vectorNumber);
  stwbrx(maskTmp, maskReg);
  eieio();
}

void OHareInterruptController::enableVector(long vectorNumber,
					    IOInterruptVector *vector)
{
  unsigned long     maskTmp;
  
  maskTmp = lwbrx(maskReg);
  maskTmp |= (1 << vectorNumber);
  stwbrx(maskTmp, maskReg);
  eieio();
  if (lwbrx(levelsReg) & (1 << vectorNumber)) {
    // lost the interrupt
    causeVector(vectorNumber, vector);
  }
}

void OHareInterruptController::causeVector(long vectorNumber,
					   IOInterruptVector */*vector*/)
{
  pendingEvents |= 1 << vectorNumber;
  parentNub->causeInterrupt(0);
}
