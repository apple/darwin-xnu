/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <IOKit/IODMAEventSource.h>
#include <IOKit/IOService.h>

#include "IOKitKernelInternal.h"


#define super IOEventSource
OSDefineMetaClassAndStructors(IODMAEventSource, IOEventSource);

bool IODMAEventSource::init(OSObject *inOwner,
			    IOService *inProvider,
			    Action inCompletion,
			    Action inNotification,
			    UInt32 inDMAIndex)
{
  IOReturn result;
  
  if (!super::init(inOwner)) return false;
  
  if (inProvider == 0) return false;
  
  dmaProvider = inProvider;
  dmaIndex = 0xFFFFFFFF;
  dmaCompletionAction = inCompletion;
  dmaNotificationAction = inNotification;
  
  dmaController = IODMAController::getController(dmaProvider, inDMAIndex);
  if (dmaController == 0) return false;
  dmaController->retain();
  
  result = dmaController->initDMAChannel(dmaProvider, this, &dmaIndex, inDMAIndex);
  if (result != kIOReturnSuccess) return false;
  
  queue_init(&dmaCommandsCompleted);
  dmaCommandsCompletedLock = IOSimpleLockAlloc();
  
  return true;
}

IODMAEventSource *IODMAEventSource::dmaEventSource(OSObject *inOwner,
						   IOService *inProvider,
						   Action inCompletion,
						   Action inNotification,
						   UInt32 inDMAIndex)
{
  IODMAEventSource *dmaES = new IODMAEventSource;
  
  if (dmaES && !dmaES->init(inOwner, inProvider, inCompletion, inNotification, inDMAIndex)) {
    dmaES->release();
    return 0;
  }
  
  return dmaES;
}

IOReturn IODMAEventSource::startDMACommand(IODMACommand *dmaCommand, IODirection direction, IOByteCount byteCount, IOByteCount byteOffset)
{
  IOReturn result;
  
  if ((dmaController == 0) || (dmaIndex == 0xFFFFFFFF)) return kIOReturnError;
  
  if (dmaSynchBusy) return kIOReturnBusy;
  
  if (dmaCompletionAction == 0) dmaSynchBusy = true;
  
  result = dmaController->startDMACommand(dmaIndex, dmaCommand, direction, byteCount, byteOffset);
  
  if (result != kIOReturnSuccess) {
    dmaSynchBusy = false;
    return result;
  }
  
  while (dmaSynchBusy) sleepGate(&dmaSynchBusy, THREAD_UNINT);
  
  return kIOReturnSuccess;
}

IOReturn IODMAEventSource::stopDMACommand(bool flush, uint64_t timeout)
{
  if ((dmaController == 0) || (dmaIndex == 0xFFFFFFFF)) return kIOReturnError;
  
  return dmaController->stopDMACommand(dmaIndex, flush, timeout);
}


IOReturn IODMAEventSource::queryDMACommand(IODMACommand **dmaCommand, IOByteCount *transferCount, bool waitForIdle)
{
  if ((dmaController == 0) || (dmaIndex == 0xFFFFFFFF)) return kIOReturnError;
  
  return dmaController->queryDMACommand(dmaIndex, dmaCommand, transferCount, waitForIdle);
}


IOByteCount IODMAEventSource::getFIFODepth()
{
  if ((dmaController == 0) || (dmaIndex == 0xFFFFFFFF)) return kIOReturnError;
  
  return dmaController->getFIFODepth(dmaIndex);
}


// protected

bool IODMAEventSource::checkForWork(void)
{
  IODMACommand     *dmaCommand = NULL;
  bool work, again;
  
  IOSimpleLockLock(dmaCommandsCompletedLock);
  work = !queue_empty(&dmaCommandsCompleted);
  if (work) {
    queue_remove_first(&dmaCommandsCompleted, dmaCommand, IODMACommand *, fCommandChain);
    again = !queue_empty(&dmaCommandsCompleted);
  } else {
    again = false;
  }
  IOSimpleLockUnlock(dmaCommandsCompletedLock);

  if (work) {
    (*dmaCompletionAction)(owner, this, dmaCommand, dmaCommand->reserved->fStatus, dmaCommand->reserved->fActualByteCount);
  }
  
  return again;
}

void IODMAEventSource::completeDMACommand(IODMACommand *dmaCommand)
{
  if (dmaCompletionAction != 0) {
    IOSimpleLockLock(dmaCommandsCompletedLock);
    queue_enter(&dmaCommandsCompleted, dmaCommand, IODMACommand *, fCommandChain);
    IOSimpleLockUnlock(dmaCommandsCompletedLock);
    
    signalWorkAvailable();
  } else {
    dmaSynchBusy = false;
    wakeupGate(&dmaSynchBusy, true);
  }
}

void IODMAEventSource::notifyDMACommand(IODMACommand *dmaCommand, IOReturn status, IOByteCount actualByteCount)
{
  dmaCommand->reserved->fStatus = status;
  dmaCommand->reserved->fActualByteCount = actualByteCount;  
  
  if (dmaNotificationAction != 0) (*dmaNotificationAction)(owner, this, dmaCommand, status, actualByteCount);
}
