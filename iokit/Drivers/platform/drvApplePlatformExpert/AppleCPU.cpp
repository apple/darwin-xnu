/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved.
 *
 *  DRI: Josh de Cesare
 *
 */

#include "AppleCPU.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOCPU

OSDefineMetaClassAndStructors(AppleCPU, IOCPU);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool AppleCPU::start(IOService *provider)
{
  kern_return_t       result;
  ml_processor_info_t this_processor_info;
  
  if (!super::start(provider)) return false;
  
  cpuIC = new IOCPUInterruptController;
  if (cpuIC == 0) return false;
  
  if (cpuIC->initCPUInterruptController(1) != kIOReturnSuccess) return false;
  cpuIC->attach(this);
  
  cpuIC->registerCPUInterruptController();
  
  this_processor_info.cpu_id           = (cpu_id_t)this;
  this_processor_info.boot_cpu         = true;
  this_processor_info.start_paddr      = 0;
  this_processor_info.supports_nap     = false;
  this_processor_info.l2cr_value       = 0;
  this_processor_info.time_base_enable = 0;
  
  // Register this CPU with mach.
  result = ml_processor_register(
				&this_processor_info,
				&machProcessor,
				&ipi_handler);
  if (result == KERN_FAILURE) return false;
  
  setCPUState(kIOCPUStateUninitalized);
  
  processor_start(machProcessor);
  
  registerService();
  
  return true;
}

void AppleCPU::initCPU(bool boot)
{
  if (boot) {
    cpuIC->enableCPUInterrupt(this);
  }
  
  setCPUState(kIOCPUStateRunning);
}

void AppleCPU::quiesceCPU(void)
{
  // Unsupported.
}

kern_return_t AppleCPU::startCPU(vm_offset_t /*start_paddr*/,
				 vm_offset_t /*arg_paddr*/)
{
  return KERN_FAILURE;
}

void AppleCPU::haltCPU(void)
{
  // Unsupported.
}

const OSSymbol *AppleCPU::getCPUName(void)
{
  return OSSymbol::withCStringNoCopy("Primary0");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
