/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#ifndef _IOKIT_CPU_H
#define _IOKIT_CPU_H

extern "C" {
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
}

#include <IOKit/IOService.h>
#include <IOKit/IOInterruptController.h>

enum {
  kIOCPUStateUnregistered = 0,
  kIOCPUStateUninitalized,
  kIOCPUStateStopped,
  kIOCPUStateRunning,
  kIOCPUStateCount
};

class IOCPUInterruptController;

extern IOCPUInterruptController *gIOCPUInterruptController;

class IOCPU : public IOService
{
  OSDeclareAbstractStructors(IOCPU);
  
private:
  OSArray                *_cpuGroup;
  UInt32                 _cpuNumber;
  UInt32                 _cpuState;
  
protected:
  IOService              *cpuNub;
  processor_t            machProcessor;
  ipi_handler_t          ipi_handler;

  struct ExpansionData { };
  ExpansionData *reserved;

  virtual void           setCPUNumber(UInt32 cpuNumber);
  virtual void           setCPUState(UInt32 cpuState);
  
public:
  static  void           initCPUs(void);
  
  virtual bool           start(IOService *provider);
  virtual IOReturn       setProperties(OSObject *properties);
  virtual void           initCPU(bool boot) = 0;
  virtual void           quiesceCPU(void) = 0;
  virtual kern_return_t  startCPU(vm_offset_t start_paddr,
				  vm_offset_t arg_paddr) = 0;
  virtual void           haltCPU(void) = 0;
  virtual void           signalCPU(IOCPU *target);
  virtual void           enableCPUTimeBase(bool enable);
  
  virtual UInt32         getCPUNumber(void);
  virtual UInt32         getCPUState(void);
  virtual OSArray        *getCPUGroup(void);
  virtual UInt32         getCPUGroupSize(void);
  virtual processor_t    getMachProcessor(void);
  
  virtual const OSSymbol *getCPUName(void) = 0;

  OSMetaClassDeclareReservedUnused(IOCPU, 0);
  OSMetaClassDeclareReservedUnused(IOCPU, 1);
  OSMetaClassDeclareReservedUnused(IOCPU, 2);
  OSMetaClassDeclareReservedUnused(IOCPU, 3);
  OSMetaClassDeclareReservedUnused(IOCPU, 4);
  OSMetaClassDeclareReservedUnused(IOCPU, 5);
  OSMetaClassDeclareReservedUnused(IOCPU, 6);
  OSMetaClassDeclareReservedUnused(IOCPU, 7);
};

void IOCPUSleepKernel(void);


class IOCPUInterruptController : public IOInterruptController
{
  OSDeclareDefaultStructors(IOCPUInterruptController);
  
private:
  int   enabledCPUs;
  
protected:  
  int   numCPUs;
  IOCPU **cpus;
  
  struct ExpansionData { };
  ExpansionData *reserved;

public:
  virtual IOReturn initCPUInterruptController(int sources);
  virtual void     registerCPUInterruptController(void);
  virtual void     setCPUInterruptProperties(IOService *service);
  virtual void     enableCPUInterrupt(IOCPU *cpu);
  
  virtual IOReturn registerInterrupt(IOService *nub, int source,
				     void *target,
				     IOInterruptHandler handler,
				     void *refCon);
  
  virtual IOReturn getInterruptType(IOService *nub, int source,
				    int *interruptType);
  
  virtual IOReturn enableInterrupt(IOService *nub, int source);
  virtual IOReturn disableInterrupt(IOService *nub, int source);
  virtual IOReturn causeInterrupt(IOService *nub, int source);
  
  virtual IOReturn handleInterrupt(void *refCon, IOService *nub,
				   int source);

  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 0);
  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 1);
  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 2);
  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 3);
  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 4);
  OSMetaClassDeclareReservedUnused(IOCPUInterruptController, 5);
};

#endif /* ! _IOKIT_CPU_H */
