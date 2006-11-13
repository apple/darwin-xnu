/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *  
 */


#ifndef _IOKIT_IOINTERRUPTCONTROLLER_H
#define _IOKIT_IOINTERRUPTCONTROLLER_H

#include <IOKit/IOLocks.h>
#include <IOKit/IOService.h>
#include <IOKit/IOInterrupts.h>


class IOSharedInterruptController;

struct IOInterruptVector {
  volatile char               interruptActive;
  volatile char               interruptDisabledSoft;
  volatile char               interruptDisabledHard;
  volatile char               interruptRegistered;
  IOLock *                    interruptLock;
  IOService *                 nub;
  long                        source;
  void *                      target;
  IOInterruptHandler          handler;
  void *                      refCon;
  IOSharedInterruptController *sharedController;
};

typedef struct IOInterruptVector IOInterruptVector;


class IOInterruptController : public IOService
{
  OSDeclareAbstractStructors(IOInterruptController);

protected:
  IOInterruptVector *vectors;
  IOSimpleLock      *controllerLock;

  struct ExpansionData { };
  ExpansionData *reserved;

public:
  virtual IOReturn registerInterrupt(IOService *nub, int source,
				     void *target,
				     IOInterruptHandler handler,
				     void *refCon);
  virtual IOReturn unregisterInterrupt(IOService *nub, int source);
  
  virtual IOReturn getInterruptType(IOService *nub, int source,
				    int *interruptType);
  
  virtual IOReturn enableInterrupt(IOService *nub, int source);
  virtual IOReturn disableInterrupt(IOService *nub, int source);
  virtual IOReturn causeInterrupt(IOService *nub, int source);
  
  virtual IOInterruptAction getInterruptHandlerAddress(void);
  virtual IOReturn handleInterrupt(void *refCon, IOService *nub,
				   int source);
  
  // Methods to be overridden for simplifed interrupt controller subclasses.
  
  virtual bool vectorCanBeShared(long vectorNumber, IOInterruptVector *vector);
  virtual void initVector(long vectorNumber, IOInterruptVector *vector);
  virtual int  getVectorType(long vectorNumber, IOInterruptVector *vector);
  virtual void disableVectorHard(long vectorNumber, IOInterruptVector *vector);
  virtual void enableVector(long vectorNumber, IOInterruptVector *vector);
  virtual void causeVector(long vectorNumber, IOInterruptVector *vector);

  OSMetaClassDeclareReservedUnused(IOInterruptController, 0);
  OSMetaClassDeclareReservedUnused(IOInterruptController, 1);
  OSMetaClassDeclareReservedUnused(IOInterruptController, 2);
  OSMetaClassDeclareReservedUnused(IOInterruptController, 3);
  OSMetaClassDeclareReservedUnused(IOInterruptController, 4);
  OSMetaClassDeclareReservedUnused(IOInterruptController, 5);
};


class IOSharedInterruptController : public IOInterruptController
{
  OSDeclareDefaultStructors(IOSharedInterruptController);
  
private:
  IOService         *provider;
  int               numVectors;
  int               vectorsRegistered;
  int               vectorsEnabled;
  volatile long     controllerDisabled;
  bool              sourceIsLevel;

  struct ExpansionData { };
  ExpansionData *reserved;

public:
  virtual IOReturn initInterruptController(IOInterruptController *parentController, OSData *parentSource);
  
  virtual IOReturn registerInterrupt(IOService *nub, int source,
                                     void *target,
                                     IOInterruptHandler handler,
                                     void *refCon);
  virtual IOReturn unregisterInterrupt(IOService *nub, int source);
  
  virtual IOReturn getInterruptType(IOService *nub, int source,
				    int *interruptType);
  
  virtual IOReturn enableInterrupt(IOService *nub, int source);
  virtual IOReturn disableInterrupt(IOService *nub, int source);
  
  virtual IOInterruptAction getInterruptHandlerAddress(void);
  virtual IOReturn handleInterrupt(void *refCon, IOService *nub, int source);

  OSMetaClassDeclareReservedUnused(IOSharedInterruptController, 0);
  OSMetaClassDeclareReservedUnused(IOSharedInterruptController, 1);
  OSMetaClassDeclareReservedUnused(IOSharedInterruptController, 2);
  OSMetaClassDeclareReservedUnused(IOSharedInterruptController, 3);
};


#endif /* ! _IOKIT_IOINTERRUPTCONTROLLER_H */
