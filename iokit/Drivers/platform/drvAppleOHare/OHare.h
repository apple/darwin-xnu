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

#ifndef _IOKIT_OHARE_H
#define _IOKIT_OHARE_H

#include <IOKit/platform/AppleMacIO.h>

#include <IOKit/IOInterrupts.h>
#include <IOKit/IOInterruptController.h>

#define kPrimaryOHare    (0)
#define kSecondaryOHare  (1)

#define kNumVectors      (32)

#define kTypeLevelMask   (0x1FF00000)

#define kEventsOffset    (0x00020)
#define kMaskOffset      (0x00024)
#define kClearOffset     (0x00028)
#define kLevelsOffset    (0x0002C)


class OHareInterruptController;

class OHare : public AppleMacIO
{
  OSDeclareDefaultStructors(OHare);
  
private:
  IOLogicalAddress         ohareBaseAddress;
  long                     ohareNum;
  OHareInterruptController *interruptController;
  
  virtual OSSymbol *getInterruptControllerName(void);
  
public:
  virtual bool start(IOService *provider);
};


class OHareInterruptController : public IOInterruptController
{
  OSDeclareDefaultStructors(OHareInterruptController);
  
private:
  IOService         *parentNub;
  IOLock            *taskLock;
  unsigned long     pendingEvents;
  unsigned long     eventsReg;
  unsigned long     maskReg;
  unsigned long     clearReg;
  unsigned long     levelsReg;
  
public:
  virtual IOReturn initInterruptController(IOService *provider,
					   IOLogicalAddress interruptControllerBase);
  
  virtual IOInterruptAction getInterruptHandlerAddress(void);
  virtual IOReturn handleInterrupt(void *refCon, IOService *nub, int source);
  
  virtual bool vectorCanBeShared(long vectorNumber, IOInterruptVector *vector);
  virtual int  getVectorType(long vectorNumber, IOInterruptVector *vector);
  virtual void disableVectorHard(long vectorNumber, IOInterruptVector *vector);
  virtual void enableVector(long vectorNumber, IOInterruptVector *vector);
  virtual void causeVector(long vectorNumber, IOInterruptVector *vector);
};


#endif /* ! _IOKIT_OHARE_H */
