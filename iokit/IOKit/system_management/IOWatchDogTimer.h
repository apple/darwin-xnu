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

#ifndef _IOWATCHDOGTIMER_H
#define _IOWATCHDOGTIMER_H

#include <IOKit/IOService.h>

class IOWatchDogTimer : public IOService
{
  OSDeclareAbstractStructors(IOWatchDogTimer);
  
protected:
  IONotifier *notifier;
  struct ExpansionData { };
  ExpansionData *reserved;
  
public:
  virtual bool start(IOService *provider);
  virtual void stop(IOService *provider);
  virtual IOReturn setProperties(OSObject *properties);
  virtual void setWatchDogTimer(UInt32 timeOut) = 0;
  
  OSMetaClassDeclareReservedUnused(IOWatchDogTimer,  0);
  OSMetaClassDeclareReservedUnused(IOWatchDogTimer,  1);
  OSMetaClassDeclareReservedUnused(IOWatchDogTimer,  2);
  OSMetaClassDeclareReservedUnused(IOWatchDogTimer,  3);
};

#endif /* !_IOWATCHDOGTIMER_H */
