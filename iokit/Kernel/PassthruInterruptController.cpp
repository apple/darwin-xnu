/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

extern "C" {
#include <mach/task.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
};

#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/PassthruInterruptController.h>

#define super IOInterruptController
OSDefineMetaClassAndStructors(PassthruInterruptController, IOInterruptController);

bool
PassthruInterruptController::init(void)
{
	if (!super::init() ||
	    !this->setProperty(gPlatformInterruptControllerName, kOSBooleanTrue) ||
	    !this->attach(getPlatform())) {
		return false;
	}
	registerService();
	if (getPlatform()->registerInterruptController(gPlatformInterruptControllerName, this) != kIOReturnSuccess) {
		return false;
	}
	if (semaphore_create(kernel_task, &child_sentinel, SYNC_POLICY_FIFO, 0) != KERN_SUCCESS) {
		return false;
	}
	return true;
}

void
PassthruInterruptController::setCPUInterruptProperties(IOService *service)
{
	if ((service->getProperty(gIOInterruptControllersKey) != NULL) &&
	    (service->getProperty(gIOInterruptSpecifiersKey) != NULL)) {
		return;
	}

	long         zero = 0;
	OSArray *specifier = OSArray::withCapacity(1);
	OSData *tmpData = OSData::withBytes(&zero, sizeof(zero));
	specifier->setObject(tmpData);
	tmpData->release();
	service->setProperty(gIOInterruptSpecifiersKey, specifier);
	specifier->release();

	OSArray *controller = OSArray::withCapacity(1);
	controller->setObject(gPlatformInterruptControllerName);
	service->setProperty(gIOInterruptControllersKey, controller);
	controller->release();
}

IOReturn
PassthruInterruptController::registerInterrupt(IOService *nub,
    int source,
    void *target,
    IOInterruptHandler handler,
    void *refCon)
{
	child_handler = handler;
	child_nub = nub;
	child_target = target;
	child_refCon = refCon;

	// Wake up waitForChildController() to tell it that AIC is registered
	semaphore_signal(child_sentinel);
	return kIOReturnSuccess;
}

void *
PassthruInterruptController::waitForChildController(void)
{
	// Block if child controller isn't registered yet.  Assumes that this
	// is only called from one place.
	semaphore_wait(child_sentinel);

	// NOTE: Assumes that AppleInterruptController passes |this| as the target argument.
	return child_target;
}

IOReturn
PassthruInterruptController::getInterruptType(IOService */*nub*/,
    int /*source*/,
    int *interruptType)
{
	if (interruptType == NULL) {
		return kIOReturnBadArgument;
	}

	*interruptType = kIOInterruptTypeLevel;

	return kIOReturnSuccess;
}

IOReturn
PassthruInterruptController::enableInterrupt(IOService */*nub*/,
    int /*source*/)
{
	return kIOReturnSuccess;
}

IOReturn
PassthruInterruptController::disableInterrupt(IOService */*nub*/,
    int /*source*/)
{
	return kIOReturnSuccess;
}

IOReturn
PassthruInterruptController::causeInterrupt(IOService */*nub*/,
    int /*source*/)
{
	ml_cause_interrupt();
	return kIOReturnSuccess;
}

IOReturn
PassthruInterruptController::handleInterrupt(void */*refCon*/,
    IOService */*nub*/,
    int source)
{
	panic("handleInterrupt shouldn't be invoked directly");
}

void
PassthruInterruptController::externalInterrupt(void)
{
	child_handler(child_target, child_refCon, child_nub, 0);
}
