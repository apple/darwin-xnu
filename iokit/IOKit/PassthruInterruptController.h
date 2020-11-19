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

#pragma once

extern "C" {
#include <mach/semaphore.h>
};

#include <IOKit/IOInterruptController.h>

/*!
 * @class       PassthruInterruptController
 * @abstract    Trivial IOInterruptController class that passes all IRQs through to a
 *              "child" driver.
 * @discussion  Waits for a "child" driver (typically loaded in a kext) to register itself,
 *              then passes the child driver's IOService pointer back via
 *              waitForChildController() so that XNU can operate on it directly.
 */
class PassthruInterruptController : public IOInterruptController
{
	OSDeclareDefaultStructors(PassthruInterruptController);

public:
	virtual bool     init(void) APPLE_KEXT_OVERRIDE;

	virtual void     *waitForChildController(void);

	virtual void     setCPUInterruptProperties(IOService *service) APPLE_KEXT_OVERRIDE;

	virtual IOReturn registerInterrupt(IOService *nub, int source,
	    void *target,
	    IOInterruptHandler handler,
	    void *refCon) APPLE_KEXT_OVERRIDE;

	virtual IOReturn getInterruptType(IOService *nub, int source,
	    int *interruptType) APPLE_KEXT_OVERRIDE;

	virtual IOReturn enableInterrupt(IOService *nub, int source) APPLE_KEXT_OVERRIDE;
	virtual IOReturn disableInterrupt(IOService *nub, int source) APPLE_KEXT_OVERRIDE;
	virtual IOReturn causeInterrupt(IOService *nub, int source) APPLE_KEXT_OVERRIDE;

	virtual IOReturn handleInterrupt(void *refCon, IOService *nub,
	    int source) APPLE_KEXT_OVERRIDE;

	virtual void externalInterrupt(void);

protected:
	IOInterruptHandler child_handler;
	void               *child_target;
	void               *child_refCon;
	IOService          *child_nub;
	semaphore_t        child_sentinel;
};
