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

#ifndef _IOKIT_APPLECPU_H
#define _IOKIT_APPLECPU_H

#include <IOKit/IOCPU.h>

class AppleCPU : public IOCPU
{
  OSDeclareDefaultStructors(AppleCPU);
  
private:
  IOCPUInterruptController *cpuIC;
  
public:
  virtual bool             start(IOService *provider);
  virtual void             initCPU(bool boot);
  virtual void             quiesceCPU(void);
  virtual kern_return_t    startCPU(vm_offset_t start_paddr,
				    vm_offset_t arg_paddr);
  virtual void             haltCPU(void);
  virtual const OSSymbol   *getCPUName(void);
};

#endif /* ! _IOKIT_APPLECPU_H */
