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
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *
 */

#ifndef _IOKIT_GENERICINTERRUPTCONTROLLER_H
#define _IOKIT_GENERICINTERRUPTCONTROLLER_H

#include <IOKit/IOInterrupts.h>
#include <IOKit/IOInterruptController.h>

class GenericInterruptController : public IOInterruptController
{
  IODeclareDefaultStructors(GenericInterruptController);
  
public:
  // There should be a method to start or init the controller.
  // Its nature is up to you.
  virtual bool start(IOService *provider);
  
  // Returns the type of a vector: level or edge.  This will probably get
  // replaced but a default method and a new method getVectorType.
  virtual IOReturn getInterruptType(IOService *nub, int source,
				    int *interruptType);
  
  // Returns a function pointer for the interrupt handler.
  // Sadly, egcs prevents this from being done by the base class.
  virtual IOInterruptAction getInterruptHandlerAddress(void);
  
  // The actual interrupt handler.
  virtual IOReturn handleInterrupt(void *refCon,
				   IOService *nub, int source);
  
  
  // Should return true if this vector can be shared.
  // The base class return false, so this method only need to be implemented
  // if the controller needs to support shared interrupts.
  // No other work is required to support shared interrupts.
  virtual bool vectorCanBeShared(long vectorNumber, IOInterruptVector *vector);
  
  // Do any hardware initalization for this vector.  Leave the vector
  // hard disabled.
  virtual void initVector(long vectorNumber, IOInterruptVector *vector);
  
  // Disable this vector at the hardware.
  virtual void disableVectorHard(long vectorNumber, IOInterruptVector *vector);
  
  // Enable this vector at the hardware.
  virtual void enableVector(long vectorNumber, IOInterruptVector *vector);
  
  // Cause an interrupt on this vector.
  virtual void causeVector(long vectorNumber, IOInterruptVector *vector);
};

#endif /* ! _IOKIT_GENERICINTERRUPTCONTROLLER_H */
