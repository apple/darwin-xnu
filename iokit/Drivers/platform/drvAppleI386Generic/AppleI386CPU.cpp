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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved.
 *
 * AppleI386CPU.cpp
 * 
 * March 6, 2000 jliu
 *    Created based on AppleCPU.
 */

#include "AppleI386CPU.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOCPU

OSDefineMetaClassAndStructors(AppleI386CPU, IOCPU);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleI386CPU::start(IOService * provider)
{
//  kern_return_t result;

    if (!super::start(provider)) return false;

    cpuIC = new AppleI386CPUInterruptController;
    if (cpuIC == 0) return false;

    if (cpuIC->initCPUInterruptController(1) != kIOReturnSuccess)
        return false;

    cpuIC->attach(this);
    
    cpuIC->registerCPUInterruptController();

#ifdef NOTYET
    // Register this CPU with mach.
    result = ml_processor_register((cpu_id_t)this, 0,
                    &machProcessor, &ipi_handler, true);
    if (result == KERN_FAILURE) return false;
#endif

    setCPUState(kIOCPUStateUninitalized);

#ifdef NOTYET
    processor_start(machProcessor);
#endif

    // Hack. Call initCPU() ourself since no one else will.
    initCPU(true);
    
    registerService();
    
    return true;
}

void AppleI386CPU::initCPU(bool /*boot*/)
{
    cpuIC->enableCPUInterrupt(this);

    setCPUState(kIOCPUStateRunning);
}

void AppleI386CPU::quiesceCPU(void)
{
}

kern_return_t AppleI386CPU::startCPU(vm_offset_t /*start_paddr*/,
				     vm_offset_t /*arg_paddr*/)
{
  return KERN_FAILURE;
}

void AppleI386CPU::haltCPU(void)
{
}

const OSSymbol * AppleI386CPU::getCPUName(void)
{
    return OSSymbol::withCStringNoCopy("Primary0");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOCPUInterruptController

OSDefineMetaClassAndStructors(AppleI386CPUInterruptController, 
                              IOCPUInterruptController);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn AppleI386CPUInterruptController::handleInterrupt(void * /*refCon*/,
                                                          IOService * /*nub*/,
                                                          int source)
{
    IOInterruptVector * vector;

    // Override the implementation in IOCPUInterruptController to
    // dispatch interrupts the old way.
    //
    // source argument is ignored, use the first IOCPUInterruptController
    // in the vector array.
    //
    vector = &vectors[0];

    if (!vector->interruptRegistered)
        return kIOReturnInvalid;
  
    vector->handler(vector->target,
                    vector->refCon,
                    vector->nub,
                    source);

    return kIOReturnSuccess;
}
